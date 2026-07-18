package com.prasiddha.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.config.CacheProperties;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Response caching (F2). Two layers, both org-scoped by default:
 * <ol>
 *   <li><b>Exact-match</b> — a hash of (normalized prompt + provider + model) keys a Redis entry.</li>
 *   <li><b>Semantic</b> — the prompt embedding is nearest-neighbour searched in a pgvector table;
 *       a hit within {@code similarity-threshold} is returned.</li>
 * </ol>
 * The semantic layer is optional and self-initialising: if the {@code vector} extension isn't
 * available it logs once and disables itself, so enabling it can never break boot. Callers must
 * only {@link #store} clean, non-degraded, non-redacted responses.
 */
@Slf4j
@Service
public class ResponseCacheService {

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final EmbeddingClient embedder;
    private final JdbcTemplate jdbcTemplate;
    private final CacheProperties props;

    private volatile Boolean semanticReady; // null = not yet attempted

    public ResponseCacheService(StringRedisTemplate redis, ObjectMapper objectMapper,
                                EmbeddingClient embedder, JdbcTemplate jdbcTemplate,
                                CacheProperties props) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.embedder = embedder;
        this.jdbcTemplate = jdbcTemplate;
        this.props = props;
    }

    /** Compact payload persisted per cache entry (never the raw prompt — only the answer + meta). */
    private record CachedPayload(String content, String provider, String model,
                                 int promptTokens, int completionTokens) {}

    public boolean isEnabled() {
        return props.isEnabled() || props.isSemanticEnabled();
    }

    /** Partition key: per-org by default, or per-key / global per config. */
    public String scopeKey(String orgId, String apiKeyId) {
        return switch (props.getScope()) {
            case KEY -> "key:" + apiKeyId;
            case GLOBAL -> "global";
            case ORG -> "org:" + orgId;
        };
    }

    /** Exact-match then semantic lookup. Returns a $0 cached response, or empty on miss/disabled. */
    public Optional<ChatResponse> lookup(ChatRequest request, String scopeKey) {
        String provider = request.providerKey();
        String model = request.getModel();

        if (props.isEnabled()) {
            try {
                String json = redis.opsForValue().get(exactKey(scopeKey, request, provider, model));
                if (json != null) {
                    return Optional.of(toResponse(objectMapper.readValue(json, CachedPayload.class)));
                }
            } catch (Exception e) {
                log.warn("Exact-match cache lookup failed (ignoring): {}", e.getMessage());
            }
        }

        if (props.isSemanticEnabled() && semanticReady()) {
            Optional<ChatResponse> hit = semanticLookup(request, scopeKey, provider, model);
            if (hit.isPresent()) {
                return hit;
            }
        }
        return Optional.empty();
    }

    /** Caches a fresh, clean response in both enabled layers. Best-effort — never throws to the caller. */
    public void store(ChatRequest request, ChatResponse response, String scopeKey) {
        if (response == null || response.getContent() == null) {
            return;
        }
        String provider = response.getProvider() != null ? response.getProvider() : request.providerKey();
        String model = response.getModel() != null ? response.getModel() : request.getModel();
        CachedPayload payload = new CachedPayload(response.getContent(), provider, model,
            tokens(response, true), tokens(response, false));

        if (props.isEnabled()) {
            try {
                redis.opsForValue().set(exactKey(scopeKey, request, provider, model),
                    objectMapper.writeValueAsString(payload), Duration.ofSeconds(props.getTtlSeconds()));
            } catch (Exception e) {
                log.warn("Exact-match cache store failed (ignoring): {}", e.getMessage());
            }
        }

        if (props.isSemanticEnabled() && semanticReady()) {
            semanticStore(request, payload, scopeKey, provider, model);
        }
    }

    // ── Exact-match helpers ────────────────────────────────────────────────

    private String exactKey(String scopeKey, ChatRequest request, String provider, String model) {
        String canonical = canonicalPrompt(request) + "|" + provider + "|" + model;
        return "respcache:" + scopeKey + ":" + sha256(canonical);
    }

    private static String canonicalPrompt(ChatRequest request) {
        StringBuilder sb = new StringBuilder();
        if (request.getSystemPrompt() != null) sb.append(request.getSystemPrompt().trim()).append('\n');
        if (request.getHistory() != null) {
            for (ChatRequest.HistoryEntry e : request.getHistory()) {
                sb.append(e.getRole()).append(':').append(e.getContent() == null ? "" : e.getContent().trim()).append('\n');
            }
        }
        sb.append(request.getUserMessage() == null ? "" : request.getUserMessage().trim());
        return sb.toString().replaceAll("\\s+", " ");
    }

    private ChatResponse toResponse(CachedPayload p) {
        return ChatResponse.builder()
            .requestId(UUID.randomUUID().toString())
            .content(p.content())
            .provider(p.provider())
            .model(p.model())
            .usage(ChatResponse.TokenUsage.builder()
                .promptTokens(p.promptTokens())
                .completionTokens(p.completionTokens())
                .totalTokens(p.promptTokens() + p.completionTokens())
                .build())
            .latencyMs(0)
            .cached(true)
            .build();
    }

    private static int tokens(ChatResponse response, boolean prompt) {
        ChatResponse.TokenUsage u = response.getUsage();
        if (u == null) return 0;
        return prompt ? u.getPromptTokens() : u.getCompletionTokens();
    }

    // ── Semantic (pgvector) layer — optional, self-initialising ─────────────

    private Optional<ChatResponse> semanticLookup(ChatRequest request, String scopeKey, String provider, String model) {
        try {
            float[] vector = embedder.embed(canonicalPrompt(request));
            String vec = toVectorLiteral(vector);
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT content, prompt_tokens, completion_tokens, provider, model, " +
                "       1 - (embedding <=> ?::vector) AS similarity " +
                "FROM response_cache WHERE scope_key = ? AND provider = ? AND model = ? " +
                "ORDER BY embedding <=> ?::vector LIMIT 1",
                vec, scopeKey, provider, model, vec);
            if (rows.isEmpty()) {
                return Optional.empty();
            }
            Map<String, Object> row = rows.get(0);
            double similarity = ((Number) row.get("similarity")).doubleValue();
            if (similarity < props.getSimilarityThreshold()) {
                return Optional.empty();
            }
            return Optional.of(toResponse(new CachedPayload(
                (String) row.get("content"), (String) row.get("provider"), (String) row.get("model"),
                intVal(row.get("prompt_tokens")), intVal(row.get("completion_tokens")))));
        } catch (Exception e) {
            log.warn("Semantic cache lookup failed (ignoring): {}", e.getMessage());
            return Optional.empty();
        }
    }

    private void semanticStore(ChatRequest request, CachedPayload payload, String scopeKey, String provider, String model) {
        try {
            float[] vector = embedder.embed(canonicalPrompt(request));
            jdbcTemplate.update(
                "INSERT INTO response_cache (scope_key, provider, model, prompt_hash, embedding, " +
                "content, prompt_tokens, completion_tokens) VALUES (?, ?, ?, ?, ?::vector, ?, ?, ?)",
                scopeKey, provider, model, sha256(canonicalPrompt(request)), toVectorLiteral(vector),
                payload.content(), payload.promptTokens(), payload.completionTokens());
            pruneScope(scopeKey);
        } catch (Exception e) {
            log.warn("Semantic cache store failed (ignoring): {}", e.getMessage());
        }
    }

    private void pruneScope(String scopeKey) {
        try {
            jdbcTemplate.update(
                "DELETE FROM response_cache WHERE scope_key = ? AND id NOT IN " +
                "(SELECT id FROM response_cache WHERE scope_key = ? ORDER BY created_at DESC LIMIT ?)",
                scopeKey, scopeKey, props.getMaxEntriesPerScope());
        } catch (DataAccessException e) {
            log.debug("Semantic cache prune skipped: {}", e.getMessage());
        }
    }

    /** Lazily create the pgvector schema; on any failure (e.g. extension absent) disable semantic caching. */
    private boolean semanticReady() {
        Boolean ready = semanticReady;
        if (ready != null) {
            return ready;
        }
        synchronized (this) {
            if (semanticReady != null) {
                return semanticReady;
            }
            try {
                jdbcTemplate.execute("CREATE EXTENSION IF NOT EXISTS vector");
                jdbcTemplate.execute(
                    "CREATE TABLE IF NOT EXISTS response_cache (" +
                    " id BIGSERIAL PRIMARY KEY," +
                    " scope_key TEXT NOT NULL," +
                    " provider TEXT NOT NULL," +
                    " model TEXT NOT NULL," +
                    " prompt_hash TEXT NOT NULL," +
                    " embedding vector(" + props.getEmbeddingDim() + ") NOT NULL," +
                    " content TEXT NOT NULL," +
                    " prompt_tokens INT," +
                    " completion_tokens INT," +
                    " created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
                jdbcTemplate.execute(
                    "CREATE INDEX IF NOT EXISTS idx_response_cache_scope ON response_cache (scope_key)");
                jdbcTemplate.execute(
                    "CREATE INDEX IF NOT EXISTS idx_response_cache_vec ON response_cache " +
                    "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)");
                log.info("Semantic response cache ready (pgvector, dim={})", props.getEmbeddingDim());
                semanticReady = true;
            } catch (Exception e) {
                log.warn("Semantic response cache unavailable — pgvector not usable, disabling. Reason: {}",
                    e.getMessage());
                semanticReady = false;
            }
            return semanticReady;
        }
    }

    private static String toVectorLiteral(float[] vector) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < vector.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(vector[i]);
        }
        return sb.append(']').toString();
    }

    private static int intVal(Object o) {
        return o instanceof Number n ? n.intValue() : 0;
    }

    static String sha256(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

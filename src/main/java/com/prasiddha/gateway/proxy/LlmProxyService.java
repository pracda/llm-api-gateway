package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.config.FallbackProperties;
import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.exception.GatewayException.ErrorClass;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.util.retry.Retry;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Routes chat requests to the correct LLM provider, resolved by string key against the
 * config-driven {@link ProviderRegistry} (F3a), and walks an ordered fallback ladder driven
 * by error class (F6):
 * <ul>
 *   <li><b>RETRYABLE_TRANSIENT</b> (5xx/timeout) — retry the same provider, then advance.</li>
 *   <li><b>USAGE_BLOCKED</b> (429/402) — skip retry, advance a rung; a FREE rung that serves
 *       the request is flagged {@code degraded} at $0.</li>
 *   <li><b>NON_RETRYABLE</b> (400/401/bad model) — thrown immediately.</li>
 * </ul>
 * Budget-exhausted callers can be degraded straight to a free rung via
 * {@link #chatDegradedToFree}.
 */
@Slf4j
@Service
public class LlmProxyService {

    private final ProviderRegistry providers;
    private final ProvidersProperties providersProperties;
    private final FallbackProperties fallbackProperties;

    @Value("${app.llm.retry.max-retries}")
    private int maxRetries;

    @Value("${app.llm.retry.backoff-ms}")
    private long backoffMs;

    /** Master switch for cross-provider laddering; when false, only the requested provider is used. */
    @Value("${app.llm.retry.fallback-enabled}")
    private boolean fallbackEnabled;

    public LlmProxyService(ProviderRegistry providers,
                           ProvidersProperties providersProperties,
                           FallbackProperties fallbackProperties) {
        this.providers = providers;
        this.providersProperties = providersProperties;
        this.fallbackProperties = fallbackProperties;
        log.info("LlmProxyService ready — providers: {}, free: {}", providers.names(), freeProviders());
    }

    // ── Non-streaming ────────────────────────────────────────────────────────

    public ChatResponse chat(ChatRequest request, int maxTokens) {
        String requested = request.providerKey();
        validateModel(requested, request.getModel());
        resolve(requested); // fail fast with 400 on an unknown provider
        return walkLadder(request, maxTokens, ladderFrom(requested), requested, null);
    }

    /**
     * Serve the request from a free provider at $0, flagged {@code degraded} — used when a
     * caller's daily budget is exhausted and the tier policy is DEGRADE_TO_FREE.
     */
    public ChatResponse chatDegradedToFree(ChatRequest request, int maxTokens, String reason) {
        List<String> free = freeProviders();
        if (free.isEmpty()) {
            throw new GatewayException("No free provider configured for degradation", HttpStatus.BAD_GATEWAY);
        }
        return walkLadder(request, maxTokens, free, request.providerKey(), reason);
    }

    /**
     * Walks {@code ladder} in order, applying the F6 error-class rules. {@code degradeReason}
     * non-null means the caller was already usage-blocked (e.g. budget) before the first rung,
     * so any FREE rung that succeeds is flagged degraded with that reason.
     */
    private ChatResponse walkLadder(ChatRequest request, int maxTokens, List<String> ladder,
                                    String requested, String degradeReason) {
        GatewayException last = null;
        boolean usageBlockedSeen = false;

        for (String key : ladder) {
            LlmProvider provider = providers.get(key);
            if (provider == null) continue;

            // A different provider can't honour the requested (provider-specific) model — let it default.
            ChatRequest attempt = key.equalsIgnoreCase(requested) ? request : request.copyForProvider();
            try {
                ChatResponse resp = attemptWithRetry(provider, attempt, maxTokens);
                boolean fellBack = !key.equalsIgnoreCase(requested);
                // Degraded = the client ended up on a FREE provider when a paid one was
                // requested — i.e. they're now on a weaker/$0 model. The reason says why.
                boolean degraded = fellBack && isFree(key) && !isFree(requested);

                ChatResponse.ChatResponseBuilder b = resp.toBuilder();
                if (fellBack) {
                    b.fellBack(true).requestedProvider(requested);
                }
                if (degraded) {
                    String reason = degradeReason != null ? degradeReason
                        : (usageBlockedSeen ? "paid_quota_exhausted" : "paid_provider_unavailable");
                    b.degraded(true).fallbackReason(reason);
                }
                return b.build();
            } catch (GatewayException e) {
                last = e;
                if (e.getErrorClass() == ErrorClass.NON_RETRYABLE) {
                    throw e; // 400/401/bad model — laddering can't help
                }
                if (e.isUsageBlocked()) {
                    usageBlockedSeen = true;
                }
                log.warn("Provider '{}' failed ({}) — advancing ladder: {}", key, e.getErrorClass(), e.getMessage());
            }
        }
        if (last != null) throw last; // exhausted — surface the last failure cleanly
        throw new GatewayException("No provider available to serve the request", HttpStatus.BAD_GATEWAY);
    }

    // ── Streaming ────────────────────────────────────────────────────────────

    /**
     * Streams from the requested provider. If it is usage-blocked BEFORE the first content
     * chunk, degrades to a free provider (a mid-stream failure cannot switch — replaying would
     * duplicate content). {@code servedProvider} is set to whichever provider actually served,
     * so the caller can attribute cost correctly.
     */
    public Flux<LlmProvider.StreamChunk> streamChat(ChatRequest request, int maxTokens,
                                                    AtomicReference<String> servedProvider) {
        String requested = request.providerKey();
        validateModel(requested, request.getModel());
        LlmProvider provider = resolve(requested);
        servedProvider.set(requested);

        Flux<LlmProvider.StreamChunk> primary = provider.streamChat(request, maxTokens)
            .retryWhen(Retry.max(maxRetries)
                .filter(this::isRetryableGatewayException)
                .doBeforeRetry(sig -> log.warn("Retrying {} stream after retryable failure (attempt {})",
                    requested, sig.totalRetries() + 1)));

        String freeKey = fallbackEnabled ? firstFreeOtherThan(requested) : null;
        if (freeKey == null) {
            return primary; // no free rung to degrade to — same-provider retry only
        }

        AtomicBoolean emitted = new AtomicBoolean(false);
        return primary
            .doOnNext(chunk -> { if (chunk.textDelta() != null) emitted.set(true); })
            .onErrorResume(err -> {
                boolean canSwitch = !emitted.get()
                    && err instanceof GatewayException ge && ge.isUsageBlocked();
                if (!canSwitch) {
                    return Flux.error(err);
                }
                servedProvider.set(freeKey);
                log.warn("Stream from '{}' usage-blocked before first chunk — degrading to free '{}'",
                    requested, freeKey);
                return providers.get(freeKey).streamChat(request.copyForProvider(), maxTokens);
            });
    }

    /** Streams directly from a free provider at $0 — for budget-exhausted DEGRADE_TO_FREE callers. */
    public Flux<LlmProvider.StreamChunk> streamDegradedToFree(ChatRequest request, int maxTokens,
                                                              AtomicReference<String> servedProvider) {
        String requested = request.providerKey();
        String freeKey = firstFreeOtherThan(requested);
        if (freeKey == null) {
            freeKey = freeProviders().stream().findFirst().orElse(null);
        }
        if (freeKey == null) {
            throw new GatewayException("No free provider configured for degradation", HttpStatus.BAD_GATEWAY);
        }
        servedProvider.set(freeKey);
        return providers.get(freeKey).streamChat(request.copyForProvider(), maxTokens)
            .retryWhen(Retry.max(maxRetries).filter(this::isRetryableGatewayException));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Provider default model, used by callers (e.g. streaming) that don't get a resolved model back. */
    public String defaultModelFor(String providerKey) {
        ProviderConfig cfg = providersProperties.get(providerKey);
        return cfg != null ? cfg.getDefaultModel() : null;
    }

    /** True when at least one free ($0) provider is configured — gate for budget degradation. */
    public boolean hasFreeProvider() {
        return !freeProviders().isEmpty();
    }

    private ChatResponse attemptWithRetry(LlmProvider provider, ChatRequest request, int maxTokens) {
        GatewayException lastError = null;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return provider.chat(request, maxTokens);
            } catch (GatewayException e) {
                if (!e.isRetryable() || attempt == maxRetries) {
                    throw e; // usage-blocked / non-retryable / retries exhausted → let the ladder decide
                }
                lastError = e;
                log.warn("Retrying {} after retryable failure (attempt {}/{}): {}",
                    provider.getProvider(), attempt + 1, maxRetries, e.getMessage());
                sleep(backoffMs * (attempt + 1));
            }
        }
        throw lastError; // unreachable in practice — loop always returns or throws above
    }

    private boolean isRetryableGatewayException(Throwable t) {
        return t instanceof GatewayException ge && ge.isRetryable();
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** The requested provider first, then the configured ladder (or registry order) minus duplicates. */
    private List<String> ladderFrom(String requested) {
        if (!fallbackEnabled) {
            return List.of(requested);
        }
        List<String> ladder = new ArrayList<>();
        ladder.add(requested);
        for (String key : baseOrder()) {
            if (!key.equalsIgnoreCase(requested) && providers.has(key)) {
                ladder.add(key);
            }
        }
        return ladder;
    }

    /** Free providers in ladder (or registry) order. */
    private List<String> freeProviders() {
        List<String> free = new ArrayList<>();
        for (String key : baseOrder()) {
            if (providers.has(key) && isFree(key)) {
                free.add(key);
            }
        }
        return free;
    }

    private String firstFreeOtherThan(String requested) {
        return freeProviders().stream()
            .filter(key -> !key.equalsIgnoreCase(requested))
            .findFirst()
            .orElse(null);
    }

    /** Configured fallback chain if set, else the provider-registry declaration order. */
    private List<String> baseOrder() {
        List<String> chain = fallbackProperties.getChain();
        if (chain != null && !chain.isEmpty()) {
            return chain.stream().map(s -> s.trim().toLowerCase()).toList();
        }
        return new ArrayList<>(providers.names());
    }

    private boolean isFree(String providerKey) {
        ProviderConfig cfg = providersProperties.get(providerKey);
        return cfg != null && cfg.isFree();
    }

    private void validateModel(String providerKey, String model) {
        if (model == null) return; // null = use provider default, always allowed
        ProviderConfig cfg = providersProperties.get(providerKey);
        if (cfg == null) {
            throw new GatewayException("Unsupported provider: " + providerKey, HttpStatus.BAD_REQUEST);
        }
        List<String> allowed = cfg.getAllowedModels();
        if (allowed == null || !allowed.contains(model)) {
            throw GatewayException.invalidModel(model, providerKey);
        }
    }

    private LlmProvider resolve(String providerKey) {
        LlmProvider provider = providers.get(providerKey);
        if (provider == null) {
            throw new GatewayException("Unsupported provider: " + providerKey, HttpStatus.BAD_REQUEST);
        }
        return provider;
    }
}

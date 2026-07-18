package com.prasiddha.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.config.CacheProperties;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * F2 — exact-match (Redis) response caching: hit/miss, org isolation, TTL, scope keys, and the
 * never-cache guards. The semantic pgvector layer is off here (needs a live pgvector DB).
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ResponseCacheService — exact-match caching")
class ResponseCacheServiceTest {

    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> valueOps;
    @Mock JdbcTemplate jdbcTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, String> backing = new HashMap<>();
    private CacheProperties props;
    private ResponseCacheService service;

    @BeforeEach
    void setUp() {
        props = new CacheProperties();
        props.setEnabled(true);
        service = new ResponseCacheService(redis, objectMapper, new StubEmbeddingClient(), jdbcTemplate, props);
    }

    /** Wires the mocked Redis value-ops to an in-memory map so store()/lookup() round-trip. */
    private void wireRedis() {
        lenient().when(redis.opsForValue()).thenReturn(valueOps);
        lenient().doAnswer(inv -> { backing.put(inv.getArgument(0), inv.getArgument(1)); return null; })
            .when(valueOps).set(anyString(), anyString(), any(Duration.class));
        lenient().when(valueOps.get(anyString())).thenAnswer(inv -> backing.get(inv.getArgument(0)));
    }

    private static ChatRequest request(String userMessage) {
        var r = new ChatRequest();
        r.setProvider("openai");
        r.setModel("gpt-4o-mini");
        r.setUserMessage(userMessage);
        return r;
    }

    private static ChatResponse response(String content) {
        return ChatResponse.builder()
            .content(content).provider("openai").model("gpt-4o-mini")
            .usage(ChatResponse.TokenUsage.builder().promptTokens(10).completionTokens(20).totalTokens(30).build())
            .build();
    }

    @Test
    void missReturnsEmpty() {
        wireRedis();
        assertThat(service.lookup(request("hello"), "org:a")).isEmpty();
    }

    @Test
    void storeThenIdenticalPromptHitsAtZeroCost() {
        wireRedis();
        service.store(request("What is our return policy?"), response("30 days."), "org:a");

        Optional<ChatResponse> hit = service.lookup(request("What is our return policy?"), "org:a");
        assertThat(hit).isPresent();
        assertThat(hit.get().isCached()).isTrue();
        assertThat(hit.get().getContent()).isEqualTo("30 days.");
        assertThat(hit.get().getLatencyMs()).isZero();
    }

    @Test
    void differentOrgDoesNotSeeAnotherOrgsCachedAnswer() {
        wireRedis();
        service.store(request("secret question"), response("secret answer"), "org:a");
        assertThat(service.lookup(request("secret question"), "org:b")).isEmpty();
    }

    @Test
    void differentModelIsADifferentCacheEntry() {
        wireRedis();
        service.store(request("same prompt"), response("gpt answer"), "org:a");
        var otherModel = request("same prompt");
        otherModel.setModel("gpt-4o");
        assertThat(service.lookup(otherModel, "org:a")).isEmpty();
    }

    @Test
    void nullContentIsNotStored() {
        wireRedis();
        service.store(request("q"), response(null), "org:a");
        assertThat(service.lookup(request("q"), "org:a")).isEmpty();
    }

    @Test
    void scopeKeyReflectsConfiguredScope() {
        assertThat(service.scopeKey("o1", "k1")).isEqualTo("org:o1");
        props.setScope(CacheProperties.Scope.KEY);
        assertThat(service.scopeKey("o1", "k1")).isEqualTo("key:k1");
        props.setScope(CacheProperties.Scope.GLOBAL);
        assertThat(service.scopeKey("o1", "k1")).isEqualTo("global");
    }

    @Test
    void fullyDisabledDoesNothingAndNeverTouchesStores() {
        props.setEnabled(false);
        props.setSemanticEnabled(false);
        assertThat(service.isEnabled()).isFalse();
        assertThat(service.lookup(request("x"), "org:a")).isEmpty();
        service.store(request("x"), response("y"), "org:a");
        verifyNoInteractions(redis, jdbcTemplate);
    }
}

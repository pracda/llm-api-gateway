package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.config.FallbackProperties;
import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Flux;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Covers the config-driven provider registry (F3a) and the free-LLM fallback ladder (F6).
 * Uses in-memory stub providers, so no network is hit; the @Value retry/fallback fields are
 * set via reflection since there's no Spring context here.
 */
@DisplayName("LlmProxyService — registry (F3a) + fallback ladder (F6)")
class LlmProxyServiceTest {

    // ── Stubs ────────────────────────────────────────────────────────────────

    /** Succeeds with a canned response naming itself. */
    private static final class StubProvider implements LlmProvider {
        private final String name;
        StubProvider(String name) { this.name = name; }
        @Override public String getProvider() { return name; }
        @Override public ChatResponse chat(ChatRequest r, int maxTokens) {
            return ChatResponse.builder().provider(name).model(r.getModel()).content("ok from " + name).build();
        }
        @Override public Flux<StreamChunk> streamChat(ChatRequest r, int maxTokens) { return Flux.empty(); }
    }

    /** Always throws the given classified error. */
    private static final class FailingProvider implements LlmProvider {
        private final String name;
        private final GatewayException error;
        FailingProvider(String name, GatewayException error) { this.name = name; this.error = error; }
        @Override public String getProvider() { return name; }
        @Override public ChatResponse chat(ChatRequest r, int maxTokens) { throw error; }
        @Override public Flux<StreamChunk> streamChat(ChatRequest r, int maxTokens) { return Flux.error(error); }
    }

    // ── Fixture builders ───────────────────────────────────────────────────────

    private static ProviderConfig cfg(String type, String defaultModel, List<String> allowed, boolean free) {
        var c = new ProviderConfig();
        c.setType(type);
        c.setDefaultModel(defaultModel);
        c.setAllowedModels(allowed);
        c.setFree(free);
        return c;
    }

    /** Builds a service over the given provider configs + registry, with laddering enabled. */
    private LlmProxyService service(Map<String, ProviderConfig> configs,
                                    Map<String, LlmProvider> registry,
                                    List<String> chain) {
        var props = new ProvidersProperties();
        props.setProviders(new LinkedHashMap<>(configs));
        var fallback = new FallbackProperties();
        if (chain != null) fallback.setChain(chain);

        var service = new LlmProxyService(new ProviderRegistry(registry), props, fallback);
        ReflectionTestUtils.setField(service, "fallbackEnabled", true);
        ReflectionTestUtils.setField(service, "maxRetries", 0);
        ReflectionTestUtils.setField(service, "backoffMs", 0L);
        return service;
    }

    private static ChatRequest request(String provider, String model) {
        var r = new ChatRequest();
        r.setProvider(provider);
        r.setModel(model);
        r.setUserMessage("hi");
        return r;
    }

    // ── F3a: config-driven registry ────────────────────────────────────────────

    @Nested
    @DisplayName("F3a — config-driven provider registry")
    class Registry {

        private LlmProxyService twoProviderService() {
            Map<String, ProviderConfig> configs = new LinkedHashMap<>();
            configs.put("openai", cfg("openai-compatible", "gpt-4o-mini", List.of("gpt-4o-mini", "gpt-4o"), false));
            configs.put("groq", cfg("openai-compatible", "llama-3.1-8b-instant", List.of("llama-3.1-8b-instant"), false));
            Map<String, LlmProvider> registry = new LinkedHashMap<>();
            registry.put("openai", new StubProvider("openai"));
            registry.put("groq", new StubProvider("groq"));
            return service(configs, registry, List.of("openai", "groq"));
        }

        @Test
        void routesToTheRequestedProvider() {
            assertThat(twoProviderService().chat(request("openai", null), 100).getProvider()).isEqualTo("openai");
        }

        @Test
        void newlyConfiguredProviderIsReachableWithNoCodeChange_andKeyIsCaseInsensitive() {
            assertThat(twoProviderService().chat(request("GROQ", "llama-3.1-8b-instant"), 100).getProvider())
                .isEqualTo("groq");
        }

        @Test
        void disallowedModelForAProviderIsRejectedWith400() {
            assertThatThrownBy(() -> twoProviderService().chat(request("openai", "gpt-5-ultra-not-allowed"), 100))
                .isInstanceOf(GatewayException.class)
                .satisfies(e -> assertThat(((GatewayException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }

        @Test
        void unknownProviderIsRejectedWith400() {
            assertThatThrownBy(() -> twoProviderService().chat(request("gemini", null), 100))
                .isInstanceOf(GatewayException.class)
                .satisfies(e -> assertThat(((GatewayException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }

        @Test
        void defaultModelIsResolvedFromConfigPerProvider() {
            LlmProxyService service = twoProviderService();
            assertThat(service.defaultModelFor("openai")).isEqualTo("gpt-4o-mini");
            assertThat(service.defaultModelFor("groq")).isEqualTo("llama-3.1-8b-instant");
            assertThat(service.defaultModelFor("nope")).isNull();
        }
    }

    // ── F6: fallback ladder + graceful degradation ─────────────────────────────

    @Nested
    @DisplayName("F6 — free-LLM graceful degradation")
    class Fallback {

        /** paid openai (fails as configured) + free groq (succeeds). */
        private LlmProxyService laddered(GatewayException openAiError) {
            Map<String, ProviderConfig> configs = new LinkedHashMap<>();
            configs.put("openai", cfg("openai-compatible", "gpt-4o-mini", List.of("gpt-4o-mini"), false));
            configs.put("groq", cfg("openai-compatible", "llama-3.1-8b-instant", List.of("llama-3.1-8b-instant"), true));
            Map<String, LlmProvider> registry = new LinkedHashMap<>();
            registry.put("openai", new FailingProvider("openai", openAiError));
            registry.put("groq", new StubProvider("groq"));
            return service(configs, registry, List.of("openai", "groq"));
        }

        @Test
        void paidQuotaExhausted_degradesToFreeProviderAtZero() {
            ChatResponse resp = laddered(GatewayException.providerUsageBlocked("openai"))
                .chat(request("openai", null), 100);

            assertThat(resp.getProvider()).isEqualTo("groq");
            assertThat(resp.isFellBack()).isTrue();
            assertThat(resp.getRequestedProvider()).isEqualTo("openai");
            assertThat(resp.isDegraded()).isTrue();
            assertThat(resp.getFallbackReason()).isEqualTo("paid_quota_exhausted");
        }

        @Test
        void transientErrorAlsoAdvancesTheLadder() {
            // 5xx/timeout is retryable; with maxRetries=0 it advances immediately to the free rung.
            ChatResponse resp = laddered(GatewayException.providerError("openai", true))
                .chat(request("openai", null), 100);
            assertThat(resp.getProvider()).isEqualTo("groq");
            assertThat(resp.isDegraded()).isTrue();
        }

        @Test
        void nonRetryableErrorIsThrownImmediately_notLaddered() {
            // A 400/bad-request from the provider must NOT silently fall through to another provider.
            assertThatThrownBy(() -> laddered(GatewayException.providerError("openai", false))
                .chat(request("openai", null), 100))
                .isInstanceOf(GatewayException.class)
                .satisfies(e -> assertThat(((GatewayException) e).getErrorClass())
                    .isEqualTo(GatewayException.ErrorClass.NON_RETRYABLE));
        }

        @Test
        void ladderExhausted_throwsLastErrorCleanly() {
            Map<String, ProviderConfig> configs = new LinkedHashMap<>();
            configs.put("openai", cfg("openai-compatible", "gpt-4o-mini", List.of(), false));
            configs.put("anthropic", cfg("anthropic", "claude-haiku-4-5-20251001", List.of(), false));
            Map<String, LlmProvider> registry = new LinkedHashMap<>();
            registry.put("openai", new FailingProvider("openai", GatewayException.providerUsageBlocked("openai")));
            registry.put("anthropic", new FailingProvider("anthropic", GatewayException.providerUsageBlocked("anthropic")));
            LlmProxyService service = service(configs, registry, List.of("openai", "anthropic"));

            assertThatThrownBy(() -> service.chat(request("openai", null), 100))
                .isInstanceOf(GatewayException.class)
                .satisfies(e -> assertThat(((GatewayException) e).isUsageBlocked()).isTrue());
        }

        @Test
        void budgetDegrade_servesFreeProviderWithBudgetReason() {
            ChatResponse resp = laddered(GatewayException.providerUsageBlocked("openai"))
                .chatDegradedToFree(request("openai", null), 100, "daily_budget_exceeded");

            assertThat(resp.getProvider()).isEqualTo("groq");
            assertThat(resp.isDegraded()).isTrue();
            assertThat(resp.getFallbackReason()).isEqualTo("daily_budget_exceeded");
        }

        @Test
        void budgetDegrade_withNoFreeProviderConfigured_throws() {
            Map<String, ProviderConfig> configs = new LinkedHashMap<>();
            configs.put("openai", cfg("openai-compatible", "gpt-4o-mini", List.of(), false));
            Map<String, LlmProvider> registry = new LinkedHashMap<>();
            registry.put("openai", new StubProvider("openai"));
            LlmProxyService service = service(configs, registry, List.of("openai"));

            assertThat(service.hasFreeProvider()).isFalse();
            assertThatThrownBy(() -> service.chatDegradedToFree(request("openai", null), 100, "daily_budget_exceeded"))
                .isInstanceOf(GatewayException.class);
        }

        @Test
        void hasFreeProvider_reflectsConfiguration() {
            assertThat(laddered(GatewayException.providerUsageBlocked("openai")).hasFreeProvider()).isTrue();
        }
    }
}

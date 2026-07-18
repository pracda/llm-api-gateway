package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * F3a — proves provider identity is config-driven: a brand-new provider added to the registry
 * (here "groq") is routable with no code change, allow-lists are enforced per provider, and an
 * unknown provider key yields a clean 400. Uses in-memory stub providers, so no network is hit.
 */
@DisplayName("LlmProxyService — config-driven provider registry (F3a)")
class LlmProxyServiceTest {

    private static ProviderConfig cfg(String type, String defaultModel, List<String> allowed) {
        var c = new ProviderConfig();
        c.setType(type);
        c.setDefaultModel(defaultModel);
        c.setAllowedModels(allowed);
        return c;
    }

    /** Records the provider it was routed to; returns a canned response without any network call. */
    private static final class StubProvider implements LlmProvider {
        private final String name;
        StubProvider(String name) { this.name = name; }
        @Override public String getProvider() { return name; }
        @Override public ChatResponse chat(ChatRequest request, int maxTokens) {
            return ChatResponse.builder().provider(name).model(request.getModel()).content("ok").build();
        }
        @Override public Flux<StreamChunk> streamChat(ChatRequest request, int maxTokens) {
            return Flux.empty();
        }
    }

    /** openai + a config-only "groq" provider, wired through the registry + props the service uses. */
    private LlmProxyService newService() {
        var props = new ProvidersProperties();
        Map<String, ProviderConfig> providerConfigs = new LinkedHashMap<>();
        providerConfigs.put("openai", cfg("openai-compatible", "gpt-4o-mini", List.of("gpt-4o-mini", "gpt-4o")));
        providerConfigs.put("groq", cfg("openai-compatible", "llama-3.1-8b-instant", List.of("llama-3.1-8b-instant")));
        props.setProviders(providerConfigs);

        Map<String, LlmProvider> registry = new LinkedHashMap<>();
        registry.put("openai", new StubProvider("openai"));
        registry.put("groq", new StubProvider("groq"));

        return new LlmProxyService(new ProviderRegistry(registry), props);
    }

    private static ChatRequest request(String provider, String model) {
        var r = new ChatRequest();
        r.setProvider(provider);
        r.setModel(model);
        r.setUserMessage("hi");
        return r;
    }

    @Test
    void routesToTheRequestedProvider() {
        ChatResponse response = newService().chat(request("openai", null), 100);
        assertThat(response.getProvider()).isEqualTo("openai");
    }

    @Test
    void newlyConfiguredProviderIsReachableWithNoCodeChange_andKeyIsCaseInsensitive() {
        // "GROQ" (upper-case) must resolve to the config-only "groq" provider.
        ChatResponse response = newService().chat(request("GROQ", "llama-3.1-8b-instant"), 100);
        assertThat(response.getProvider()).isEqualTo("groq");
    }

    @Test
    void disallowedModelForAProviderIsRejectedWith400() {
        assertThatThrownBy(() -> newService().chat(request("openai", "gpt-5-ultra-not-allowed"), 100))
            .isInstanceOf(GatewayException.class)
            .satisfies(e -> assertThat(((GatewayException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void unknownProviderIsRejectedWith400() {
        assertThatThrownBy(() -> newService().chat(request("gemini", null), 100))
            .isInstanceOf(GatewayException.class)
            .satisfies(e -> assertThat(((GatewayException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void defaultModelIsResolvedFromConfigPerProvider() {
        LlmProxyService service = newService();
        assertThat(service.defaultModelFor("openai")).isEqualTo("gpt-4o-mini");
        assertThat(service.defaultModelFor("groq")).isEqualTo("llama-3.1-8b-instant");
        assertThat(service.defaultModelFor("nope")).isNull();
    }
}

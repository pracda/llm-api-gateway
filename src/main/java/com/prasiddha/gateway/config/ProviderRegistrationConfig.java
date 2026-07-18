package com.prasiddha.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.proxy.AnthropicProvider;
import com.prasiddha.gateway.proxy.LlmProvider;
import com.prasiddha.gateway.proxy.OpenAiCompatibleProvider;
import com.prasiddha.gateway.proxy.ProviderRegistry;
import com.prasiddha.gateway.service.CanaryTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns each {@code app.llm.providers.<key>} entry into an {@link LlmProvider} instance and
 * exposes them as a single {@link ProviderRegistry} bean (F3a). Adding a provider is now a
 * config-only change — no new bean class, no enum edit, no recompile.
 */
@Slf4j
@Configuration
public class ProviderRegistrationConfig {

    static final String TYPE_OPENAI_COMPATIBLE = "openai-compatible";
    static final String TYPE_ANTHROPIC         = "anthropic";

    @Bean
    public ProviderRegistry providerRegistry(
        ProvidersProperties props,
        WebClient webClient,
        CanaryTokenProvider canaryTokenProvider,
        ObjectMapper objectMapper
    ) {
        Map<String, LlmProvider> registry = new LinkedHashMap<>();

        props.getProviders().forEach((rawName, cfg) -> {
            String name = rawName.trim().toLowerCase();
            String type = cfg.getType() == null ? "" : cfg.getType().trim().toLowerCase();

            LlmProvider provider = switch (type) {
                case TYPE_OPENAI_COMPATIBLE ->
                    new OpenAiCompatibleProvider(name, cfg, webClient, canaryTokenProvider, objectMapper);
                case TYPE_ANTHROPIC ->
                    new AnthropicProvider(name, cfg, webClient, canaryTokenProvider, objectMapper);
                default -> throw new IllegalStateException(
                    "Provider '" + name + "' has unknown type '" + cfg.getType()
                        + "'. Expected '" + TYPE_OPENAI_COMPATIBLE + "' or '" + TYPE_ANTHROPIC + "'.");
            };
            registry.put(name, provider);
        });

        if (registry.isEmpty()) {
            throw new IllegalStateException(
                "No LLM providers configured — set at least one under app.llm.providers.*");
        }

        log.info("Provider registry ready — {} provider(s): {}", registry.size(), registry.keySet());
        return new ProviderRegistry(registry);
    }
}

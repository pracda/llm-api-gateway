package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Declarative provider registry — {@code app.llm.providers.<key>} — that makes adding an
 * LLM backend a config-only change (F3a). Each entry is turned into an {@link
 * com.prasiddha.gateway.proxy.LlmProvider} bean by {@code ProviderRegistrationConfig}.
 *
 * <p>{@code openai-compatible} covers OpenAI itself plus Groq, OpenRouter, Together, Ollama,
 * etc. (all speak the OpenAI chat-completions wire format); {@code anthropic} is handled by
 * the dedicated {@code AnthropicProvider}. Insertion order is preserved so the first entry
 * acts as the natural fallback target until the F6 ladder replaces that heuristic.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm")
public class ProvidersProperties {

    /** Keyed by lower-case provider name; LinkedHashMap keeps declaration order for fallback. */
    private Map<String, ProviderConfig> providers = new LinkedHashMap<>();

    /** Case-insensitive lookup by provider key. */
    public ProviderConfig get(String providerKey) {
        return providerKey == null ? null : providers.get(providerKey.trim().toLowerCase());
    }

    @Data
    public static class ProviderConfig {
        /** "openai-compatible" or "anthropic". */
        private String type;
        /** Root URL; the provider appends its own path (e.g. {@code /v1/chat/completions}). */
        private String baseUrl;
        private String apiKey;
        /** Anthropic only — the {@code anthropic-version} header value. */
        private String apiVersion;
        private String defaultModel;
        /** Explicit models a caller may request; empty = only the default (omit {@code model}). */
        private List<String> allowedModels = List.of();
        private int timeoutSeconds = 120;
        /** True for $0 backends (Groq free tier, Ollama, …). The F6 ladder degrades to these. */
        private boolean free = false;
    }
}

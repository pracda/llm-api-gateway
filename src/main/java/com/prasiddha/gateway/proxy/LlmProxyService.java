package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.util.retry.Retry;

import java.util.List;

/**
 * Routes chat requests to the correct LLM provider, resolved by string key against the
 * config-driven {@link ProviderRegistry} (F3a). Model allow-lists and per-provider defaults
 * come from {@link ProvidersProperties}, so a new provider is reachable with no code change.
 */
@Slf4j
@Service
public class LlmProxyService {

    private final ProviderRegistry providers;
    private final ProvidersProperties providersProperties;

    @Value("${app.llm.retry.max-retries}")
    private int maxRetries;

    @Value("${app.llm.retry.backoff-ms}")
    private long backoffMs;

    @Value("${app.llm.retry.fallback-enabled}")
    private boolean fallbackEnabled;

    public LlmProxyService(ProviderRegistry providers, ProvidersProperties providersProperties) {
        this.providers = providers;
        this.providersProperties = providersProperties;
        log.info("LlmProxyService ready — providers: {}", providers.names());
    }

    public ChatResponse chat(ChatRequest request, int maxTokens) {
        String providerKey = request.providerKey();
        validateModel(providerKey, request.getModel());
        LlmProvider primary = resolve(providerKey);
        log.info("Routing to: {}", providerKey);

        try {
            return attemptWithRetry(primary, request, maxTokens);
        } catch (GatewayException e) {
            if (!e.isRetryable() || !fallbackEnabled) {
                throw e;
            }
            LlmProvider fallback = fallbackFor(providerKey);
            if (fallback == null) {
                throw e;
            }
            log.warn("Falling back from {} to {} after retryable failure: {}",
                providerKey, fallback.getProvider(), e.getMessage());
            ChatResponse response = fallback.chat(request, maxTokens);
            return response.toBuilder()
                .requestedProvider(providerKey)
                .fellBack(true)
                .build();
        }
    }

    public Flux<LlmProvider.StreamChunk> streamChat(ChatRequest request, int maxTokens) {
        String providerKey = request.providerKey();
        validateModel(providerKey, request.getModel());
        LlmProvider provider = resolve(providerKey);
        log.info("Routing stream to: {}", providerKey);

        // Retry-before-first-chunk only — once a chunk has reached the subscriber, replaying
        // the stream (same or different provider) would look like a broken duplicate response
        // to the client. No cross-provider fallback for streaming, regardless of fallback-enabled.
        return provider.streamChat(request, maxTokens)
            .retryWhen(Retry.max(maxRetries)
                .filter(this::isRetryableGatewayException)
                .doBeforeRetry(signal -> log.warn("Retrying {} stream after retryable failure (attempt {})",
                    providerKey, signal.totalRetries() + 1)));
    }

    /** Provider default model, used by callers (e.g. streaming) that don't get a resolved model back. */
    public String defaultModelFor(String providerKey) {
        ProviderConfig cfg = providersProperties.get(providerKey);
        return cfg != null ? cfg.getDefaultModel() : null;
    }

    private ChatResponse attemptWithRetry(LlmProvider provider, ChatRequest request, int maxTokens) {
        GatewayException lastError = null;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return provider.chat(request, maxTokens);
            } catch (GatewayException e) {
                if (!e.isRetryable() || attempt == maxRetries) {
                    throw e;
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

    /**
     * First configured provider that isn't the requested one. This "any other provider"
     * heuristic is F3a's carry-over of the original two-provider behaviour; F6 replaces it
     * with an ordered, error-class-driven fallback ladder.
     */
    private LlmProvider fallbackFor(String requestedKey) {
        for (String name : providers.names()) {
            if (!name.equalsIgnoreCase(requestedKey)) {
                return providers.get(name);
            }
        }
        return null;
    }

    private void validateModel(String providerKey, String model) {
        if (model == null) return; // null = use provider default, always allowed
        ProviderConfig cfg = providersProperties.get(providerKey);
        if (cfg == null) {
            // Unknown provider — surface it as a routing error, not a model error.
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

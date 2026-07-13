package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.util.retry.Retry;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Routes chat requests to the correct LLM provider.
 * All LlmProvider implementations are auto-discovered via Spring DI.
 */
@Slf4j
@Service
public class LlmProxyService {

    private final Map<ChatRequest.LlmProvider, LlmProvider> providers;
    private final Set<String> openAiAllowedModels;
    private final Set<String> anthropicAllowedModels;

    @Value("${app.llm.retry.max-retries}")
    private int maxRetries;

    @Value("${app.llm.retry.backoff-ms}")
    private long backoffMs;

    @Value("${app.llm.retry.fallback-enabled}")
    private boolean fallbackEnabled;

    public LlmProxyService(
        List<LlmProvider> providerList,
        @Value("${app.llm.openai.allowed-models}") String openAiAllowedModelsCsv,
        @Value("${app.llm.anthropic.allowed-models}") String anthropicAllowedModelsCsv
    ) {
        this.providers = providerList.stream()
            .collect(Collectors.toMap(LlmProvider::getProvider, Function.identity()));
        this.openAiAllowedModels = toSet(openAiAllowedModelsCsv);
        this.anthropicAllowedModels = toSet(anthropicAllowedModelsCsv);
        log.info("LlmProxyService ready — providers: {}", providers.keySet());
    }

    public ChatResponse chat(ChatRequest request, int maxTokens) {
        validateModel(request.getProvider(), request.getModel());
        LlmProvider primary = resolve(request.getProvider());
        log.info("Routing to: {}", request.getProvider());

        try {
            return attemptWithRetry(primary, request, maxTokens);
        } catch (GatewayException e) {
            if (!e.isRetryable() || !fallbackEnabled) {
                throw e;
            }
            LlmProvider fallback = fallbackFor(request.getProvider());
            if (fallback == null) {
                throw e;
            }
            log.warn("Falling back from {} to {} after retryable failure: {}",
                request.getProvider(), fallback.getProvider(), e.getMessage());
            ChatResponse response = fallback.chat(request, maxTokens);
            return response.toBuilder()
                .requestedProvider(request.getProvider().name())
                .fellBack(true)
                .build();
        }
    }

    public Flux<LlmProvider.StreamChunk> streamChat(ChatRequest request, int maxTokens) {
        validateModel(request.getProvider(), request.getModel());
        LlmProvider provider = resolve(request.getProvider());
        log.info("Routing stream to: {}", request.getProvider());

        // Retry-before-first-chunk only — once a chunk has reached the subscriber, replaying
        // the stream (same or different provider) would look like a broken duplicate response
        // to the client. No cross-provider fallback for streaming, regardless of fallback-enabled.
        return provider.streamChat(request, maxTokens)
            .retryWhen(Retry.max(maxRetries)
                .filter(this::isRetryableGatewayException)
                .doBeforeRetry(signal -> log.warn("Retrying {} stream after retryable failure (attempt {})",
                    request.getProvider(), signal.totalRetries() + 1)));
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

    private LlmProvider fallbackFor(ChatRequest.LlmProvider requested) {
        for (Map.Entry<ChatRequest.LlmProvider, LlmProvider> entry : providers.entrySet()) {
            if (entry.getKey() != requested) {
                return entry.getValue();
            }
        }
        return null;
    }

    private void validateModel(ChatRequest.LlmProvider provider, String model) {
        if (model == null) return; // null = use provider default, always allowed
        Set<String> allowed = provider == ChatRequest.LlmProvider.OPENAI ? openAiAllowedModels : anthropicAllowedModels;
        if (!allowed.contains(model)) {
            throw GatewayException.invalidModel(model, provider.name());
        }
    }

    private LlmProvider resolve(ChatRequest.LlmProvider requested) {
        LlmProvider provider = providers.get(requested);
        if (provider == null) {
            throw new GatewayException("Unsupported provider: " + requested, HttpStatus.BAD_REQUEST);
        }
        return provider;
    }

    private static Set<String> toSet(String csv) {
        return Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toUnmodifiableSet());
    }
}

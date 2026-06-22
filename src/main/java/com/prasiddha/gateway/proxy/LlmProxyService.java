package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
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

    public LlmProxyService(List<LlmProvider> providerList) {
        this.providers = providerList.stream()
            .collect(Collectors.toMap(LlmProvider::getProvider, Function.identity()));
        log.info("LlmProxyService ready — providers: {}", providers.keySet());
    }

    public ChatResponse chat(ChatRequest request) {
        LlmProvider provider = providers.get(request.getProvider());
        if (provider == null) {
            throw new GatewayException("Unsupported provider: " + request.getProvider(), HttpStatus.BAD_REQUEST);
        }
        log.info("Routing to: {}", request.getProvider());
        return provider.chat(request);
    }
}

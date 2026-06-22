package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;

/**
 * Contract every LLM provider must implement.
 * Adding a new provider (e.g. Gemini) = implement this interface only.
 */
public interface LlmProvider {
    ChatRequest.LlmProvider getProvider();
    ChatResponse chat(ChatRequest request);
}

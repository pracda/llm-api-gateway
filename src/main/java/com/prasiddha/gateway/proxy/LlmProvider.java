package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import reactor.core.publisher.Flux;

/**
 * Contract every LLM provider must implement.
 * Adding a new provider (e.g. Gemini) = implement this interface only.
 */
public interface LlmProvider {
    ChatRequest.LlmProvider getProvider();

    /** maxTokens caps the completion length — enforces the caller's API key tier budget. */
    ChatResponse chat(ChatRequest request, int maxTokens);

    /**
     * Token-by-token streaming variant. Emits StreamChunk.text(...) for each delta,
     * then exactly one StreamChunk.done(usage) as the final element before completion.
     */
    Flux<StreamChunk> streamChat(ChatRequest request, int maxTokens);

    record StreamChunk(String textDelta, boolean done, ChatResponse.TokenUsage finalUsage) {
        static StreamChunk text(String delta) {
            return new StreamChunk(delta, false, null);
        }
        static StreamChunk done(ChatResponse.TokenUsage usage) {
            return new StreamChunk(null, true, usage);
        }
    }
}

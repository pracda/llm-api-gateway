package com.prasiddha.gateway.proxy;

import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import reactor.core.publisher.Flux;

/**
 * Contract every LLM provider must implement.
 *
 * As of F3a, providers are identified by a lower-case string key (e.g. "openai",
 * "anthropic", "groq", "ollama") rather than a fixed enum, so a new OpenAI-compatible
 * backend can be added via configuration alone — see {@code app.llm.providers.*} and
 * {@code ProviderRegistrationConfig}.
 */
public interface LlmProvider {
    /** Lower-case provider key this instance serves (matches its {@code app.llm.providers.<key>} entry). */
    String getProvider();

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

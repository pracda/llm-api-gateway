package com.prasiddha.gateway.service;

/**
 * Turns text into an embedding vector. Implementations call an OpenAI-compatible
 * {@code /v1/embeddings} endpoint. Shared by F1 (semantic injection detection) and F2
 * (semantic caching). Callers are responsible for fail-open behaviour on exceptions.
 */
public interface EmbeddingClient {

    /** Embeds the text; throws if the embedder call fails. */
    float[] embed(String text);

    /** True when an embedder endpoint is configured (base URL present). */
    boolean isConfigured();
}

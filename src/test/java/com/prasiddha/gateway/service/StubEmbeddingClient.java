package com.prasiddha.gateway.service;

import java.util.HashMap;
import java.util.Map;

/**
 * Deterministic in-memory {@link EmbeddingClient} for tests — maps specific texts to fixed
 * vectors so cosine similarity is fully controlled; unmapped texts get an orthogonal default.
 * Set {@code failure} to make {@code embed} throw (to exercise fail-open behaviour).
 */
class StubEmbeddingClient implements EmbeddingClient {

    final Map<String, float[]> vectors = new HashMap<>();
    boolean configured = true;
    RuntimeException failure;
    /** Returned for any text not explicitly mapped — orthogonal to [1,0]. */
    float[] defaultVector = {0f, 1f};

    StubEmbeddingClient map(String text, float... vector) {
        vectors.put(text, vector);
        return this;
    }

    @Override
    public boolean isConfigured() {
        return configured;
    }

    @Override
    public float[] embed(String text) {
        if (failure != null) {
            throw failure;
        }
        return vectors.getOrDefault(text, defaultVector);
    }
}

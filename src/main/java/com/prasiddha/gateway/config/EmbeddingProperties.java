package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Shared embeddings source ({@code app.llm.embeddings.*}) used by semantic injection
 * detection (F1) and, later, semantic response caching (F2). Any OpenAI-compatible
 * {@code /v1/embeddings} endpoint works — hosted OpenAI by default, or point {@code base-url}
 * at a local Ollama ({@code http://localhost:11434}, model {@code nomic-embed-text}) for a
 * self-contained $0 setup with no code change.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm.embeddings")
public class EmbeddingProperties {

    /** Root URL of an OpenAI-compatible embeddings API. Blank disables embedding-based features. */
    private String baseUrl = "";

    /** Bearer key; may be blank for a local/keyless embedder (e.g. Ollama). */
    private String apiKey = "";

    private String model = "text-embedding-3-small";

    private int timeoutSeconds = 10;
}

package com.prasiddha.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.prasiddha.gateway.config.EmbeddingProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;

/**
 * {@link EmbeddingClient} backed by any OpenAI-compatible {@code /v1/embeddings} endpoint.
 * Content is embedded transiently and never stored — only downstream scores are (OWASP LLM #06).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OpenAiCompatibleEmbeddingClient implements EmbeddingClient {

    private final WebClient webClient;
    private final EmbeddingProperties props;

    @Override
    public boolean isConfigured() {
        return props.getBaseUrl() != null && !props.getBaseUrl().isBlank();
    }

    @Override
    public float[] embed(String text) {
        if (!isConfigured()) {
            throw new IllegalStateException("No embeddings endpoint configured (app.llm.embeddings.base-url)");
        }
        String url = stripTrailingSlash(props.getBaseUrl()) + "/v1/embeddings";

        WebClient.RequestBodySpec spec = webClient.post().uri(url).contentType(MediaType.APPLICATION_JSON);
        if (props.getApiKey() != null && !props.getApiKey().isBlank()) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, "Bearer " + props.getApiKey());
        }

        JsonNode root = spec
            .bodyValue(Map.of("model", props.getModel(), "input", text))
            .retrieve()
            .bodyToMono(JsonNode.class)
            .timeout(Duration.ofSeconds(props.getTimeoutSeconds()))
            .block();

        JsonNode embedding = root == null ? null : root.path("data").path(0).path("embedding");
        if (embedding == null || !embedding.isArray() || embedding.isEmpty()) {
            throw new IllegalStateException("Embeddings response had no vector");
        }
        float[] vector = new float[embedding.size()];
        for (int i = 0; i < embedding.size(); i++) {
            vector[i] = (float) embedding.get(i).asDouble();
        }
        return vector;
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}

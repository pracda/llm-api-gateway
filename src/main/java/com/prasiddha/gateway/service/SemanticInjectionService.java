package com.prasiddha.gateway.service;

import com.prasiddha.gateway.config.SemanticProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Semantic prompt-injection detection (F1). Embeds the incoming prompt and compares it (max
 * cosine similarity) against a curated corpus of known-jailbreak exemplars, mapping the result
 * to a 0–{@code weight} contribution that feeds the existing jailbreak score. This catches
 * paraphrased/obfuscated attacks the regex layer misses.
 *
 * <p>Guarantees: <b>fail-open</b> (any embedder/corpus problem yields a zero contribution, never
 * a block), and <b>content-free</b> (prompt and corpus are embedded transiently; nothing but the
 * score is ever persisted). Corpus vectors are computed lazily on first use and cached.
 */
@Slf4j
@Service
public class SemanticInjectionService {

    public record SemanticResult(double similarity, int contribution, boolean matched) {
        static SemanticResult none() { return new SemanticResult(0.0, 0, false); }
    }

    private final EmbeddingClient embedder;
    private final SemanticProperties props;
    private final List<String> corpus;

    private volatile float[][] corpusVectors;   // lazily computed, cached on success
    private volatile boolean corpusEmbedFailed; // avoid hammering a down embedder every request

    @Autowired
    public SemanticInjectionService(EmbeddingClient embedder, SemanticProperties props, ResourceLoader resourceLoader) {
        this(embedder, props, loadCorpus(resourceLoader, props.getCorpusResource()));
    }

    /** Test/explicit-corpus constructor. */
    SemanticInjectionService(EmbeddingClient embedder, SemanticProperties props, List<String> corpus) {
        this.embedder = embedder;
        this.props = props;
        this.corpus = corpus;
        log.info("SemanticInjectionService — enabled={}, corpus exemplars={}", props.isEnabled(), corpus.size());
    }

    /**
     * Scores the prompt's semantic similarity to the jailbreak corpus. Returns a zero result
     * (fail-open) when disabled, unconfigured, or on any error.
     */
    public SemanticResult score(String prompt) {
        if (!props.isEnabled() || !embedder.isConfigured() || corpus.isEmpty() || prompt == null || prompt.isBlank()) {
            return SemanticResult.none();
        }
        try {
            float[][] vectors = corpusVectors();
            if (vectors.length == 0) {
                return SemanticResult.none();
            }
            float[] promptVector = embedder.embed(prompt);

            double best = 0.0;
            for (float[] vector : vectors) {
                best = Math.max(best, cosine(promptVector, vector));
            }

            double floor = props.getSimilarityFloor();
            double normalised = (best - floor) / (1.0 - floor);
            int contribution = (int) Math.round(clamp(normalised, 0.0, 1.0) * props.getWeight());
            boolean matched = best >= props.getSimilarityThreshold();
            return new SemanticResult(best, contribution, matched);
        } catch (Exception e) {
            // Fail-open — a semantic problem must never block legitimate traffic.
            log.warn("Semantic injection scan failed open (contribution 0): {}", e.getMessage());
            return SemanticResult.none();
        }
    }

    /** Double-checked lazy embedding of the corpus; caches on success, backs off on failure. */
    private float[][] corpusVectors() {
        float[][] local = corpusVectors;
        if (local != null) {
            return local;
        }
        synchronized (this) {
            if (corpusVectors != null) {
                return corpusVectors;
            }
            if (corpusEmbedFailed) {
                return new float[0][];
            }
            try {
                float[][] vectors = new float[corpus.size()][];
                for (int i = 0; i < corpus.size(); i++) {
                    vectors[i] = embedder.embed(corpus.get(i));
                }
                corpusVectors = vectors;
                log.info("Embedded {} jailbreak corpus exemplars for semantic detection", vectors.length);
                return vectors;
            } catch (Exception e) {
                corpusEmbedFailed = true; // don't retry every request; restart to re-attempt
                log.warn("Could not embed jailbreak corpus — semantic detection disabled this run: {}", e.getMessage());
                return new float[0][];
            }
        }
    }

    static double cosine(float[] a, float[] b) {
        if (a == null || b == null || a.length != b.length || a.length == 0) {
            return 0.0;
        }
        double dot = 0, normA = 0, normB = 0;
        for (int i = 0; i < a.length; i++) {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        if (normA == 0 || normB == 0) {
            return 0.0;
        }
        return dot / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private static double clamp(double v, double min, double max) {
        return Math.max(min, Math.min(max, v));
    }

    private static List<String> loadCorpus(ResourceLoader resourceLoader, String location) {
        List<String> lines = new ArrayList<>();
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists()) {
            log.warn("Jailbreak corpus not found at '{}' — semantic detection will be inert", location);
            return lines;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    lines.add(trimmed);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to read jailbreak corpus '{}': {}", location, e.getMessage());
        }
        return lines;
    }
}

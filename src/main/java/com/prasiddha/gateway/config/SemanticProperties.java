package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Semantic prompt-injection detection policy (F1) — {@code app.security.input.semantic.*}.
 * Complements the regex layer by catching paraphrased/obfuscated jailbreaks via embedding
 * similarity to a curated corpus. Always fail-open: an embedder outage never blocks traffic.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.security.input.semantic")
public class SemanticProperties {

    /** Master switch. When off (or the embedder is unconfigured), scanning is regex-only. */
    private boolean enabled = false;

    /** Cosine similarity at/above which a prompt is treated as a match and blocked. */
    private double similarityThreshold = 0.82;

    /** Similarity below this contributes 0 to the score (noise floor). */
    private double similarityFloor = 0.60;

    /** Maximum points the semantic pass can add to the jailbreak score. */
    private int weight = 60;

    /** Skip the semantic pass when the regex score already exceeds this (near/at a block). */
    private int grayZoneMax = 59;

    /** Skip trivially short prompts — not worth an embedding call. */
    private int minPromptChars = 20;

    /** Classpath (or file) location of the newline-separated jailbreak exemplar corpus. */
    private String corpusResource = "classpath:jailbreak-corpus.txt";
}

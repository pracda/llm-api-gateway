package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Response caching (F2) — {@code app.cache.*}. Turns cost tracking into cost saving: identical
 * (exact-match, Redis) and near-identical (semantic, pgvector) prompts return a cached answer at
 * $0 instead of paying the provider again.
 *
 * <p>Both layers are OFF by default so the live box is unaffected until explicitly enabled. The
 * semantic layer additionally requires a Postgres image with the {@code vector} extension
 * available (e.g. {@code pgvector/pgvector:pg16}); it self-disables if the extension is absent,
 * so enabling it can never break boot.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.cache")
public class CacheProperties {

    /** How cache entries are partitioned — never share across orgs unless explicitly GLOBAL. */
    public enum Scope { ORG, KEY, GLOBAL }

    /** Exact-match (Redis) layer. */
    private boolean enabled = false;

    /** Semantic (pgvector) layer — requires the vector extension; self-disables if unavailable. */
    private boolean semanticEnabled = false;

    /** Cosine similarity at/above which a semantic cache entry is considered a hit. */
    private double similarityThreshold = 0.93;

    private long ttlSeconds = 3600;

    private Scope scope = Scope.ORG;

    /** Cap on semantic-cache rows per scope; oldest are pruned past this. */
    private int maxEntriesPerScope = 1000;

    /** Embedding dimension of the configured embeddings model (text-embedding-3-small = 1536). */
    private int embeddingDim = 1536;
}

package com.prasiddha.gateway.proxy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Immutable lookup of configured {@link LlmProvider} instances keyed by lower-case provider
 * name (F3a). Deliberately a concrete type rather than a raw {@code Map<String, LlmProvider>}
 * bean: Spring treats a {@code Map<String, LlmProvider>} injection point as "all beans of
 * that type keyed by bean name", which would clash with the programmatically-built providers.
 * Declaration order from {@code app.llm.providers.*} is preserved.
 */
public class ProviderRegistry {

    private final Map<String, LlmProvider> byName;

    public ProviderRegistry(Map<String, LlmProvider> byName) {
        this.byName = new LinkedHashMap<>(byName);
    }

    /** Provider for the given key (case-insensitive), or null if none is configured. */
    public LlmProvider get(String name) {
        return name == null ? null : byName.get(name.trim().toLowerCase());
    }

    public boolean has(String name) {
        return get(name) != null;
    }

    /** Configured provider keys, in declaration order. */
    public Set<String> names() {
        return Collections.unmodifiableSet(byName.keySet());
    }

    public int size() {
        return byName.size();
    }
}

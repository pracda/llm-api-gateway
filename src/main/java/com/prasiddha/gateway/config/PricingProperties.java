package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Per-model $ pricing (app.llm.pricing.{provider}.{model}) used to compute request cost
 * from token counts.
 *
 * <p>As of F3a the provider dimension is a dynamic map keyed by provider name, so a new
 * provider's pricing (including {@code $0} free-tier entries) is added by config alone —
 * no new field, no code change. Lookup is case-insensitive on the provider key.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm")
public class PricingProperties {

    /** provider key → (model id → price). Binds app.llm.pricing.{provider}.{model}. */
    private Map<String, Map<String, ModelPricing>> pricing = new HashMap<>();

    /** Returns null if the provider/model combination has no configured price. */
    public ModelPricing lookup(String provider, String model) {
        if (provider == null || model == null) return null;
        Map<String, ModelPricing> table = pricing.get(provider.trim().toLowerCase());
        return table == null ? null : table.get(model);
    }

    @Data
    public static class ModelPricing {
        private double inputPerMillion;
        private double outputPerMillion;
    }
}

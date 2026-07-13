package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Per-model $ pricing (app.llm.pricing.{provider}.{model}) used to compute request cost
 * from token counts. The only nested-map config in the app, so it's the one place a
 * @ConfigurationProperties bean is used instead of the flat @Value pattern used elsewhere.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm.pricing")
public class PricingProperties {

    private Map<String, ModelPricing> openai = new HashMap<>();
    private Map<String, ModelPricing> anthropic = new HashMap<>();

    /** Returns null if the provider/model combination has no configured price. */
    public ModelPricing lookup(String provider, String model) {
        if (provider == null || model == null) return null;
        Map<String, ModelPricing> table = "openai".equalsIgnoreCase(provider) ? openai : anthropic;
        return table.get(model);
    }

    @Data
    public static class ModelPricing {
        private double inputPerMillion;
        private double outputPerMillion;
    }
}

package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Smart-routing policy (F3b) — {@code app.llm.routing.*}. Engaged only when a chat request
 * sends {@code "model": "auto"}; explicit model choices are always honoured.
 *
 * <p>The router picks between a cheap {@code simple} model and a premium {@code complex} one
 * using signals the gateway already computes (prompt size, jailbreak score), then applies a
 * tier cap and a remaining-budget floor. All thresholds are config so operators tune policy
 * without code changes.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm.routing")
public class RoutingProperties {

    /** Master switch. When off, {@code "model": "auto"} falls back to the requested provider's default. */
    private boolean enabled = true;

    /** Cheap/default target for simple traffic. */
    private ModelRef simple;

    /** Premium target for complex or suspicious traffic. */
    private ModelRef complex;

    /** Prompts at/above this many characters route to {@code complex}. */
    private int complexityCharThreshold = 600;

    /** Jailbreak risk score at/above this also routes to {@code complex} (premium models are more robust). */
    private int suspiciousScoreThreshold = 40;

    /** Only these API-key tiers may reach {@code complex}; others are capped to {@code simple}. */
    private List<String> premiumTiers = List.of("STANDARD", "ENTERPRISE");

    /** When remaining daily budget drops below this fraction of the cap, force {@code simple}. */
    private double budgetFloorFraction = 0.15;

    @Data
    public static class ModelRef {
        private String provider;
        private String model;
    }
}

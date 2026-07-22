package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Smart-routing policy (F3b) — {@code app.llm.routing.*}. Two forms:
 * <ul>
 *   <li><b>Task routing:</b> a request's {@code "task"} label is mapped to a {@code profiles.<task>}
 *       (provider, model) — deterministic, caller-declared orchestration (coding, reasoning, …).</li>
 *   <li><b>Complexity routing:</b> {@code "model":"auto"} picks between {@code simple} and
 *       {@code complex} from prompt size / jailbreak score, with a tier cap and budget floor.</li>
 * </ul>
 * All targets are config, so operators tune the policy — and add providers like DeepSeek/Kimi —
 * without code changes.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm.routing")
public class RoutingProperties {

    /** Master switch. When off, {@code "model":"auto"} and {@code task} fall back to the requested provider. */
    private boolean enabled = true;

    /** Task label → (provider, model). Caller sends {@code "task":"<name>"} to route here. */
    private Map<String, ModelRef> profiles = new LinkedHashMap<>();

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

package com.prasiddha.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Free-LLM graceful degradation policy (F6) — {@code app.llm.fallback.*}.
 *
 * <p>The {@code chain} is the ordered fallback ladder the proxy walks on a usage-blocked
 * provider; when empty it defaults to the provider-registry declaration order. Budget
 * exhaustion is policy-driven: {@code HARD_BLOCK} keeps the original 402, {@code
 * DEGRADE_TO_FREE} routes to a free rung instead. The policy can be overridden per API-key
 * tier.
 */
@Data
@Component
@ConfigurationProperties(prefix = "app.llm.fallback")
public class FallbackProperties {

    public enum BudgetPolicy { HARD_BLOCK, DEGRADE_TO_FREE }

    /** Ordered provider ladder (lower-case keys). Empty = use registry declaration order. */
    private List<String> chain = new ArrayList<>();

    /** Default action when a caller's daily budget is exhausted. */
    private BudgetPolicy onBudgetExhausted = BudgetPolicy.HARD_BLOCK;

    /** Optional per-tier override, keyed by ApiKey.Tier name (e.g. TRIAL, STANDARD, ENTERPRISE). */
    private Map<String, BudgetPolicy> budgetPolicyByTier = new HashMap<>();

    /** Resolves the effective budget policy for a tier, falling back to the global default. */
    public BudgetPolicy policyForTier(String tier) {
        if (tier != null) {
            BudgetPolicy override = budgetPolicyByTier.get(tier.trim().toUpperCase());
            if (override != null) {
                return override;
            }
        }
        return onBudgetExhausted;
    }
}

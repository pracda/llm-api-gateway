package com.prasiddha.gateway.service;

import com.prasiddha.gateway.config.RoutingProperties;
import com.prasiddha.gateway.config.RoutingProperties.ModelRef;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.request.ChatRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Smart routing (F3b): when a caller sends {@code "model": "auto"}, chooses a concrete
 * (provider, model) from signals the gateway already computes — prompt size and jailbreak
 * score — then applies the tier cap and remaining-budget floor from {@link RoutingProperties}.
 * Explicit model choices never reach this service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RoutingService {

    public static final String AUTO = "auto";

    private final RoutingProperties props;

    public record RoutingDecision(String provider, String model, String reason) {}

    /** True when the caller asked the gateway to pick the model ({@code "model": "auto"}). */
    public boolean isAutoRequested(String model) {
        return model != null && model.trim().equalsIgnoreCase(AUTO);
    }

    /** True when routing is switched on and both model tiers are configured. */
    public boolean isEnabled() {
        return props.isEnabled() && isComplete(props.getSimple()) && isComplete(props.getComplex());
    }

    /**
     * Picks a (provider, model) for an auto request.
     *
     * @param dailyBudgetUsd caller's daily cap, or null for unlimited
     * @param currentSpendUsd spend already accumulated today
     */
    public RoutingDecision decide(ChatRequest request, ApiKey apiKey, int jailbreakScore,
                                  Double dailyBudgetUsd, double currentSpendUsd) {
        int size = promptSize(request);
        boolean bigPrompt = size >= props.getComplexityCharThreshold();
        boolean suspicious = jailbreakScore >= props.getSuspiciousScoreThreshold();

        ModelRef target;
        String reason;
        if (bigPrompt || suspicious) {
            target = props.getComplex();
            reason = suspicious ? "elevated_risk" : "complex_prompt";
        } else {
            target = props.getSimple();
            reason = "simple_prompt";
        }

        // Tier cap — non-premium tiers never reach the premium model.
        if (target == props.getComplex() && !isPremiumTier(apiKey)) {
            target = props.getSimple();
            reason = "tier_capped";
        }

        // Budget floor — when little of the daily cap remains, force the cheap model.
        if (dailyBudgetUsd != null && dailyBudgetUsd > 0) {
            double remaining = dailyBudgetUsd - currentSpendUsd;
            if (remaining < props.getBudgetFloorFraction() * dailyBudgetUsd) {
                target = props.getSimple();
                reason = "budget_floor";
            }
        }

        RoutingDecision decision = new RoutingDecision(
            target.getProvider() == null ? null : target.getProvider().trim().toLowerCase(),
            target.getModel(), reason);
        log.info("Auto-routed to {}/{} ({}) — promptChars={} jailbreak={} tier={}",
            decision.provider(), decision.model(), reason, size, jailbreakScore,
            apiKey.getTier() != null ? apiKey.getTier().name() : "?");
        return decision;
    }

    private boolean isPremiumTier(ApiKey apiKey) {
        if (apiKey.getTier() == null) return false;
        return props.getPremiumTiers().stream().anyMatch(t -> t.equalsIgnoreCase(apiKey.getTier().name()));
    }

    /** Total character length of the prompt: user message + system prompt + any history turns. */
    private int promptSize(ChatRequest request) {
        int size = length(request.getUserMessage()) + length(request.getSystemPrompt());
        if (request.getHistory() != null) {
            for (ChatRequest.HistoryEntry entry : request.getHistory()) {
                size += length(entry.getContent());
            }
        }
        return size;
    }

    private static int length(String s) {
        return s == null ? 0 : s.length();
    }

    private static boolean isComplete(ModelRef ref) {
        return ref != null && ref.getProvider() != null && !ref.getProvider().isBlank()
            && ref.getModel() != null && !ref.getModel().isBlank();
    }
}

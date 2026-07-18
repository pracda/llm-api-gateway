package com.prasiddha.gateway.service;

import com.prasiddha.gateway.config.RoutingProperties;
import com.prasiddha.gateway.config.RoutingProperties.ModelRef;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.service.RoutingService.RoutingDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F3b — smart routing picks (provider, model) for "model":"auto" requests from prompt size
 * and jailbreak score, then applies the tier cap and budget floor. Pure unit tests.
 */
@DisplayName("RoutingService — auto model selection")
class RoutingServiceTest {

    private static RoutingService service() {
        var props = new RoutingProperties();
        props.setSimple(ref("openai", "gpt-4o-mini"));
        props.setComplex(ref("anthropic", "claude-sonnet-5"));
        // defaults: enabled, complexity-char-threshold 600, suspicious-score-threshold 40,
        //           premium-tiers [STANDARD, ENTERPRISE], budget-floor-fraction 0.15
        return new RoutingService(props);
    }

    private static ModelRef ref(String provider, String model) {
        var r = new ModelRef();
        r.setProvider(provider);
        r.setModel(model);
        return r;
    }

    private static ApiKey key(ApiKey.Tier tier, Double dailyBudgetUsd) {
        return ApiKey.builder().tier(tier).dailyBudgetUsd(dailyBudgetUsd).build();
    }

    private static ChatRequest autoRequest(int promptChars) {
        var r = new ChatRequest();
        r.setProvider("openai");
        r.setModel("auto");
        r.setUserMessage("x".repeat(promptChars));
        return r;
    }

    @Nested
    @DisplayName("Trigger detection")
    class Trigger {
        @Test void autoKeywordIsDetectedCaseInsensitively() {
            assertThat(service().isAutoRequested("auto")).isTrue();
            assertThat(service().isAutoRequested("AUTO")).isTrue();
            assertThat(service().isAutoRequested("gpt-4o")).isFalse();
            assertThat(service().isAutoRequested(null)).isFalse();
        }

        @Test void isEnabledRequiresBothModelTiersConfigured() {
            assertThat(service().isEnabled()).isTrue();
            var half = new RoutingProperties();
            half.setSimple(ref("openai", "gpt-4o-mini"));   // complex missing
            assertThat(new RoutingService(half).isEnabled()).isFalse();
            var off = new RoutingProperties();
            off.setEnabled(false);
            off.setSimple(ref("openai", "gpt-4o-mini"));
            off.setComplex(ref("anthropic", "claude-sonnet-5"));
            assertThat(new RoutingService(off).isEnabled()).isFalse();
        }
    }

    @Nested
    @DisplayName("Model selection")
    class Selection {
        @Test void shortPromptRoutesToSimple() {
            RoutingDecision d = service().decide(autoRequest(50), key(ApiKey.Tier.STANDARD, null), 0, null, 0);
            assertThat(d.provider()).isEqualTo("openai");
            assertThat(d.model()).isEqualTo("gpt-4o-mini");
            assertThat(d.reason()).isEqualTo("simple_prompt");
        }

        @Test void longPromptRoutesToComplexForPremiumTier() {
            RoutingDecision d = service().decide(autoRequest(800), key(ApiKey.Tier.STANDARD, null), 0, null, 0);
            assertThat(d.provider()).isEqualTo("anthropic");
            assertThat(d.model()).isEqualTo("claude-sonnet-5");
            assertThat(d.reason()).isEqualTo("complex_prompt");
        }

        @Test void suspiciousPromptRoutesToComplexEvenWhenShort() {
            RoutingDecision d = service().decide(autoRequest(50), key(ApiKey.Tier.ENTERPRISE, null), 55, null, 0);
            assertThat(d.model()).isEqualTo("claude-sonnet-5");
            assertThat(d.reason()).isEqualTo("elevated_risk");
        }
    }

    @Nested
    @DisplayName("Guards")
    class Guards {
        @Test void trialTierIsCappedToSimpleEvenForComplexPrompts() {
            RoutingDecision d = service().decide(autoRequest(800), key(ApiKey.Tier.TRIAL, null), 0, null, 0);
            assertThat(d.model()).isEqualTo("gpt-4o-mini");
            assertThat(d.reason()).isEqualTo("tier_capped");
        }

        @Test void lowRemainingBudgetForcesSimple() {
            // dailyBudget 10, spent 9.5 → remaining 0.5 < 0.15*10 = 1.5 → force simple.
            RoutingDecision d = service().decide(autoRequest(800), key(ApiKey.Tier.STANDARD, 10.0), 0, 10.0, 9.5);
            assertThat(d.model()).isEqualTo("gpt-4o-mini");
            assertThat(d.reason()).isEqualTo("budget_floor");
        }

        @Test void ampleBudgetKeepsComplex() {
            RoutingDecision d = service().decide(autoRequest(800), key(ApiKey.Tier.STANDARD, 10.0), 0, 10.0, 1.0);
            assertThat(d.model()).isEqualTo("claude-sonnet-5");
            assertThat(d.reason()).isEqualTo("complex_prompt");
        }
    }
}

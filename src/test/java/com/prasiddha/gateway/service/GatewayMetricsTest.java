package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F5 — metrics are derived from the audit entry (requests/cost/latency/tokens/jailbreak) plus a
 * few call-site counters (cache/degrade/fallback), all against a real SimpleMeterRegistry.
 */
@DisplayName("GatewayMetrics — Prometheus meter emission")
class GatewayMetricsTest {

    private SimpleMeterRegistry registry;
    private GatewayMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new GatewayMetrics(registry);
    }

    private static AuditLog audit(AuditLog.Outcome outcome, double costUsd, long latencyMs, int jailbreak) {
        return AuditLog.builder()
            .provider("openai").model("gpt-4o-mini").outcome(outcome)
            .promptTokens(10).completionTokens(20).latencyMs(latencyMs)
            .costUsd(costUsd).jailbreakScore(jailbreak).build();
    }

    @Test
    void recordAuditEmitsRequestCostLatencyTokenAndJailbreakMeters() {
        metrics.recordAudit(audit(AuditLog.Outcome.SUCCESS, 0.0125, 150, 5));

        assertThat(registry.get("gateway.requests.total")
            .tag("provider", "openai").tag("model", "gpt-4o-mini").tag("outcome", "SUCCESS")
            .counter().count()).isEqualTo(1.0);
        assertThat(registry.get("gateway.cost.usd.total").tag("provider", "openai")
            .counter().count()).isEqualTo(0.0125);
        assertThat(registry.get("gateway.tokens.total").tag("provider", "openai")
            .counter().count()).isEqualTo(30.0);
        assertThat(registry.get("gateway.provider.latency").tag("provider", "openai")
            .summary().count()).isEqualTo(1);
        assertThat(registry.get("gateway.jailbreak.score").summary().count()).isEqualTo(1);
    }

    @Test
    void blockedOutcomesAreCountedByOutcomeTag() {
        metrics.recordAudit(audit(AuditLog.Outcome.BLOCKED_INPUT_INJECTION, 0.0, 0, 90));
        assertThat(registry.get("gateway.requests.total").tag("outcome", "BLOCKED_INPUT_INJECTION")
            .counter().count()).isEqualTo(1.0);
        // No provider call happened → no cost/latency meters were created.
        assertThat(registry.find("gateway.cost.usd.total").counter()).isNull();
    }

    @Test
    void nullEntryIsIgnored() {
        metrics.recordAudit(null); // must not throw
        assertThat(registry.find("gateway.requests.total").counter()).isNull();
    }

    @Test
    void cacheHitAndMissAreDistinctSeries() {
        metrics.recordCache(true);
        metrics.recordCache(false);
        metrics.recordCache(true);
        assertThat(registry.get("gateway.cache.lookups.total").tag("result", "hit").counter().count()).isEqualTo(2.0);
        assertThat(registry.get("gateway.cache.lookups.total").tag("result", "miss").counter().count()).isEqualTo(1.0);
    }

    @Test
    void degradeAndFallbackCounters() {
        metrics.recordDegraded("paid_quota_exhausted");
        metrics.recordFallback();
        assertThat(registry.get("gateway.degraded.total").tag("reason", "paid_quota_exhausted")
            .counter().count()).isEqualTo(1.0);
        assertThat(registry.get("gateway.fallbacks.total").counter().count()).isEqualTo(1.0);
    }
}

package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Prometheus/Micrometer instrumentation (F5). Most meters are derived once, from the single
 * audit chokepoint ({@link AuditService#log}), so every request outcome is counted for both
 * /chat and /chat/stream without scattering meter calls through the pipeline. A few signals
 * not present on the audit row (cache hits, degrade/fallback) are recorded at their call sites.
 *
 * <p>Tag cardinality is kept bounded: provider/model/outcome are low-cardinality; no per-user
 * or per-org tags. Scrape at {@code /actuator/prometheus}.
 */
@Component
public class GatewayMetrics {

    private final MeterRegistry registry;
    private final DistributionSummary jailbreakScore;

    public GatewayMetrics(MeterRegistry registry) {
        this.registry = registry;
        this.jailbreakScore = DistributionSummary.builder("gateway.jailbreak.score")
            .description("Distribution of input jailbreak risk scores (0-100)")
            .publishPercentiles(0.5, 0.95)
            .register(registry);
    }

    /** Emits request/latency/cost/token/jailbreak meters from a completed audit entry. */
    public void recordAudit(AuditLog entry) {
        if (entry == null) {
            return;
        }
        String provider = entry.getProvider() != null ? entry.getProvider() : "none";
        String model = entry.getModel() != null ? entry.getModel() : "none";
        String outcome = entry.getOutcome() != null ? entry.getOutcome().name() : "UNKNOWN";

        Counter.builder("gateway.requests.total")
            .description("Total gateway requests by provider, model and outcome")
            .tag("provider", provider).tag("model", model).tag("outcome", outcome)
            .register(registry)
            .increment();

        jailbreakScore.record(entry.getJailbreakScore());

        if (entry.getLatencyMs() > 0) {
            DistributionSummary.builder("gateway.provider.latency")
                .description("Provider round-trip latency in milliseconds")
                .baseUnit("milliseconds")
                .tag("provider", provider)
                .register(registry)
                .record(entry.getLatencyMs());
        }
        if (entry.getCostUsd() > 0) {
            Counter.builder("gateway.cost.usd.total")
                .description("Cumulative provider spend in USD by provider")
                .tag("provider", provider)
                .register(registry)
                .increment(entry.getCostUsd());
        }
        int tokens = entry.getPromptTokens() + entry.getCompletionTokens();
        if (tokens > 0) {
            Counter.builder("gateway.tokens.total")
                .description("Cumulative tokens processed by provider")
                .tag("provider", provider)
                .register(registry)
                .increment(tokens);
        }
    }

    /** Cache lookup outcome (F2): result = "hit" | "miss". */
    public void recordCache(boolean hit) {
        Counter.builder("gateway.cache.lookups.total")
            .description("Response-cache lookups by result")
            .tag("result", hit ? "hit" : "miss")
            .register(registry)
            .increment();
    }

    /** A response served by a free provider after a paid one failed/was usage-blocked (F6). */
    public void recordDegraded(String reason) {
        Counter.builder("gateway.degraded.total")
            .description("Requests degraded to a free provider by reason")
            .tag("reason", reason != null ? reason : "unknown")
            .register(registry)
            .increment();
    }

    /** A cross-provider fallback occurred (F6 ladder). */
    public void recordFallback() {
        Counter.builder("gateway.fallbacks.total")
            .description("Cross-provider fallbacks")
            .register(registry)
            .increment();
    }
}

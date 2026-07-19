package com.prasiddha.gateway.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F4 — the mid-stream leak scanner catches a canary token or secret in streamed output, including
 * when it's split across chunk boundaries (via the sliding overlap buffer), and lets clean content
 * through untouched.
 */
@DisplayName("StreamLeakScanner — mid-stream canary/secret detection")
class StreamLeakScannerTest {

    private static final String CANARY = "cnry-test-abc123";

    private static OutputScanService outputScan() {
        // findStreamingLeak() only uses the canary provider + secret patterns, so the other
        // @Value-driven fields are irrelevant here and can stay at their defaults.
        return new OutputScanService(new CanaryTokenProvider(CANARY));
    }

    @Test
    void cleanContentPassesThrough() {
        var scanner = new StreamLeakScanner(outputScan());
        assertThat(scanner.inspect("Your order ships ")).isNull();
        assertThat(scanner.inspect("tomorrow afternoon.")).isNull();
    }

    @Test
    void canaryInASingleChunkIsCaughtAsPromptLeak() {
        var scanner = new StreamLeakScanner(outputScan());
        OutputScanService.StreamLeak leak = scanner.inspect("here is the secret " + CANARY + " oops");
        assertThat(leak).isNotNull();
        assertThat(leak.promptLeak()).isTrue();
    }

    @Test
    void canarySplitAcrossChunksIsStillCaught() {
        var scanner = new StreamLeakScanner(outputScan());
        // Split the canary across three deltas — none contains it whole.
        assertThat(scanner.inspect("leaking cnry-")).isNull();
        assertThat(scanner.inspect("test-")).isNull();
        OutputScanService.StreamLeak leak = scanner.inspect("abc123 now");
        assertThat(leak).isNotNull();
        assertThat(leak.promptLeak()).isTrue();
    }

    @Test
    void secretCredentialPatternIsCaught() {
        var scanner = new StreamLeakScanner(outputScan());
        String openAiKey = "sk-" + "A".repeat(48);
        OutputScanService.StreamLeak leak = scanner.inspect("token: " + openAiKey);
        assertThat(leak).isNotNull();
        assertThat(leak.promptLeak()).isFalse();
    }

    @Test
    void secretSplitAcrossChunksIsStillCaught() {
        var scanner = new StreamLeakScanner(outputScan());
        assertThat(scanner.inspect("key is sk-" + "A".repeat(20))).isNull();
        OutputScanService.StreamLeak leak = scanner.inspect("A".repeat(28) + " end");
        assertThat(leak).isNotNull();
        assertThat(leak.promptLeak()).isFalse();
    }
}

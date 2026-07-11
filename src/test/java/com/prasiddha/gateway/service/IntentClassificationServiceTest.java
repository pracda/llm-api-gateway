package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog.IntentClassification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("IntentClassificationService — deterministic bucketing from existing signals")
class IntentClassificationServiceTest {

    private final IntentClassificationService service = new IntentClassificationService();

    @Test
    @DisplayName("clean, low-score request is NORMAL")
    void cleanRequestIsNormal() {
        var result = service.classify(new IntentClassificationService.Signals(false, false, false, false, 0));
        assertThat(result.classification()).isEqualTo(IntentClassification.NORMAL);
        assertThat(result.reason()).isNull();
    }

    @Test
    @DisplayName("jailbreak score in the 40-69 band is SUSPICIOUS")
    void midJailbreakScoreIsSuspicious() {
        var result = service.classify(new IntentClassificationService.Signals(false, false, false, false, 55));
        assertThat(result.classification()).isEqualTo(IntentClassification.SUSPICIOUS);
        assertThat(result.reason()).contains("55");
    }

    @Test
    @DisplayName("jailbreak score >= 70 is MALICIOUS")
    void highJailbreakScoreIsMalicious() {
        var result = service.classify(new IntentClassificationService.Signals(false, false, false, false, 85));
        assertThat(result.classification()).isEqualTo(IntentClassification.MALICIOUS);
    }

    @Test
    @DisplayName("blocked input (injection/PII) is MALICIOUS regardless of score")
    void blockedInputIsMalicious() {
        var result = service.classify(new IntentClassificationService.Signals(false, false, true, false, 0));
        assertThat(result.classification()).isEqualTo(IntentClassification.MALICIOUS);
    }

    @Test
    @DisplayName("blocked output (unsafe content/prompt leak) is MALICIOUS")
    void blockedOutputIsMalicious() {
        var result = service.classify(new IntentClassificationService.Signals(false, false, false, true, 0));
        assertThat(result.classification()).isEqualTo(IntentClassification.MALICIOUS);
    }

    @Test
    @DisplayName("a request that tips an account lockout is MALICIOUS even with a clean score")
    void accountLockedIsMalicious() {
        var result = service.classify(new IntentClassificationService.Signals(false, true, false, false, 0));
        assertThat(result.classification()).isEqualTo(IntentClassification.MALICIOUS);
    }

    @Test
    @DisplayName("a blocked IP is MALICIOUS regardless of every other signal")
    void ipBlockedIsMalicious() {
        var result = service.classify(new IntentClassificationService.Signals(true, false, false, false, 0));
        assertThat(result.classification()).isEqualTo(IntentClassification.MALICIOUS);
    }
}

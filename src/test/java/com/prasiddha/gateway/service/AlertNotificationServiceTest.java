package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

@DisplayName("AlertNotificationService — opt-in webhook delivery, severity-gated")
class AlertNotificationServiceTest {

    private WebClient webClient;
    private AlertNotificationService service;

    @BeforeEach
    void setUp() {
        webClient = mock(WebClient.class);
        service = new AlertNotificationService(webClient);
    }

    @Test
    @DisplayName("does nothing when no webhook URL is configured (default)")
    void noWebhookConfigured_doesNothing() {
        ReflectionTestUtils.setField(service, "webhookUrl", "");

        service.notifyIfHighSeverity(alert(SecurityAlert.Severity.HIGH));

        verifyNoInteractions(webClient);
    }

    @Test
    @DisplayName("does nothing for non-HIGH severity even when a webhook is configured")
    void nonHighSeverity_doesNothing() {
        ReflectionTestUtils.setField(service, "webhookUrl", "https://hooks.example.com/services/x");

        service.notifyIfHighSeverity(alert(SecurityAlert.Severity.MEDIUM));
        service.notifyIfHighSeverity(alert(SecurityAlert.Severity.LOW));

        verifyNoInteractions(webClient);
    }

    private SecurityAlert alert(SecurityAlert.Severity severity) {
        return SecurityAlert.builder()
            .username("alice")
            .type(SecurityAlert.Type.REPEATED_INJECTION)
            .severity(severity)
            .message("test message")
            .build();
    }
}

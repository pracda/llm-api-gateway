package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Fire-and-forget webhook delivery for HIGH-severity alerts (Slack-compatible
 * "text" payload — also works with Microsoft Teams/Discord webhook relays
 * that accept the same shape). Disabled by default (blank URL) — opt in via
 * ALERT_WEBHOOK_URL. Never blocks or affects request handling: delivery
 * failures are logged and swallowed, same fail-open posture as the rest of
 * ThreatDetectionService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AlertNotificationService {

    private final WebClient webClient;

    @Value("${app.security.alert-webhook-url:}")
    private String webhookUrl;

    public void notifyIfHighSeverity(SecurityAlert alert) {
        if (alert.getSeverity() != SecurityAlert.Severity.HIGH) return;
        if (webhookUrl == null || webhookUrl.isBlank()) return;

        String text = String.format(":rotating_light: *%s*%s\n%s",
            alert.getType().friendlyLabel(),
            alert.getUsername() != null ? " — user `" + alert.getUsername() + "`" : "",
            alert.getMessage());

        webClient.post()
            .uri(webhookUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of("text", text))
            .retrieve()
            .toBodilessEntity()
            .doOnError(e -> log.warn("Alert webhook delivery failed, ignoring: {}", e.getMessage()))
            .onErrorResume(e -> Mono.empty())
            .subscribe();
    }
}

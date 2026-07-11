package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Fans out gateway activity to the live admin dashboard (see SseEmitterRegistry).
 * Kept as a thin, self-contained wrapper so swapping the transport (e.g. to
 * Redis Pub/Sub, if this ever becomes multi-instance) is a one-file change.
 */
@Service
@RequiredArgsConstructor
public class RealtimeEventPublisher {

    private final SseEmitterRegistry registry;

    public void publishAudit(AuditLog entry) {
        registry.broadcast("audit", AuditEvent.from(entry));
    }

    public void publishAlert(SecurityAlert alert) {
        registry.broadcast("alert", AlertEvent.from(alert));
    }

    public record AuditEvent(
        String id, String username, String provider, String model, String outcome,
        String blockReason, int promptTokens, int completionTokens, long latencyMs,
        int httpStatus, int jailbreakScore, String ipAddress, String apiKeyId, boolean streamed,
        String intentClassification, String intentReason, String createdAt
    ) {
        static AuditEvent from(AuditLog a) {
            return new AuditEvent(
                a.getId(), a.getUserId(), a.getProvider(), a.getModel(), a.getOutcome().name(),
                a.getBlockReason(), a.getPromptTokens(), a.getCompletionTokens(), a.getLatencyMs(),
                a.getHttpStatus(), a.getJailbreakScore(), a.getIpAddress(), a.getApiKeyId(), a.isStreamed(),
                a.getIntentClassification().name(), a.getIntentReason(),
                a.getCreatedAt().toString()
            );
        }
    }

    public record AlertEvent(
        String id, String username, String type, String label, String severity, String message,
        boolean autoLockApplied, String createdAt
    ) {
        static AlertEvent from(SecurityAlert s) {
            return new AlertEvent(
                s.getId(), s.getUsername(), s.getType().name(), s.getType().friendlyLabel(), s.getSeverity().name(),
                s.getMessage(), s.isAutoLockApplied(), s.getCreatedAt().toString()
            );
        }
    }
}

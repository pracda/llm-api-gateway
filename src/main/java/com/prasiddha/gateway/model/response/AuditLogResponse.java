package com.prasiddha.gateway.model.response;

import com.prasiddha.gateway.model.entity.AuditLog;

/** Shared across AdminController and AdminOrganizationController — both expose audit log listings. */
public record AuditLogResponse(
    String id,
    String userId,
    String provider,
    String model,
    String outcome,
    String blockReason,
    int promptTokens,
    int completionTokens,
    long latencyMs,
    int httpStatus,
    boolean streamed,
    String intentClassification,
    String intentReason,
    String createdAt
) {
    public static AuditLogResponse from(AuditLog log) {
        return new AuditLogResponse(
            log.getId(),
            log.getUserId(),
            log.getProvider(),
            log.getModel(),
            log.getOutcome().name(),
            log.getBlockReason(),
            log.getPromptTokens(),
            log.getCompletionTokens(),
            log.getLatencyMs(),
            log.getHttpStatus(),
            log.isStreamed(),
            log.getIntentClassification().name(),
            log.getIntentReason(),
            log.getCreatedAt().toString()
        );
    }
}

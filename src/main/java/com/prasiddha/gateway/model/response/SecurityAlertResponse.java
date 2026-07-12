package com.prasiddha.gateway.model.response;

import com.prasiddha.gateway.model.entity.SecurityAlert;

/** Shared across AdminAlertController and AdminUserController — both list security alerts. */
public record SecurityAlertResponse(
    String id, String username, String type, String label, String severity, String message,
    boolean autoLockApplied, boolean acknowledged, String acknowledgedBy, String acknowledgedAt, String createdAt
) {
    public static SecurityAlertResponse from(SecurityAlert a) {
        return new SecurityAlertResponse(
            a.getId(), a.getUsername(), a.getType().name(), a.getType().friendlyLabel(),
            a.getSeverity().name(), a.getMessage(),
            a.isAutoLockApplied(), a.isAcknowledged(), a.getAcknowledgedBy(),
            a.getAcknowledgedAt() != null ? a.getAcknowledgedAt().toString() : null,
            a.getCreatedAt().toString()
        );
    }
}

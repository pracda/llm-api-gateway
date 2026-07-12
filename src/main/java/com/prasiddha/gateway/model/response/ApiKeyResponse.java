package com.prasiddha.gateway.model.response;

import com.prasiddha.gateway.model.entity.ApiKey;

/** Shared across AdminOrganizationController and AdminUserController — both list API keys, masked (no key hash/raw secret). */
public record ApiKeyResponse(
    String id, String organizationId, String username, String name, String keyPrefix,
    String tier, int requestsPerDay, int maxTokensPerRequest, String status,
    String createdAt, String expiresAt, String lastUsedAt, String createdByAdmin
) {
    public static ApiKeyResponse from(ApiKey k) {
        return new ApiKeyResponse(
            k.getId(), k.getOrganizationId(), k.getUsername(), k.getName(), k.getKeyPrefix(),
            k.getTier().name(), k.getRequestsPerDay(), k.getMaxTokensPerRequest(), k.getStatus().name(),
            k.getCreatedAt().toString(),
            k.getExpiresAt() != null ? k.getExpiresAt().toString() : null,
            k.getLastUsedAt() != null ? k.getLastUsedAt().toString() : null,
            k.getCreatedByAdmin()
        );
    }
}

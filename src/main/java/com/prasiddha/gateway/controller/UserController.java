package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.model.response.CreateApiKeyResponse;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.OrganizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Endpoints any authenticated user can call to see their own usage, and (since the
 * self-service signup addition) to get their own API key without waiting on an admin.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User")
public class UserController {

    /** Marks self-issued keys in ApiKey.createdByAdmin — distinguishes them from real admin grants in the audit trail. */
    private static final String SELF_SERVICE_MARKER = "self-service";

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final ApiKeyService apiKeyService;
    private final OrganizationService organizationService;

    @GetMapping("/me")
    @Operation(
        summary = "Your profile and usage stats",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> me(
        @AuthenticationPrincipal String username
    ) {
        GatewayUser user = userRepository.findByUsername(username).orElseThrow();

        Instant last24h = Instant.now().minusSeconds(86400);
        Instant last1h  = Instant.now().minusSeconds(3600);

        long requestsToday    = auditLogRepository.countByUserIdAndCreatedAtAfter(username, last24h);
        long requestsLastHour = auditLogRepository.countByUserIdAndCreatedAtAfter(username, last1h);
        Long tokensToday      = auditLogRepository.sumTokensByUserAndPeriod(username, last24h);

        return ResponseEntity.ok(Map.of(
            "username",          user.getUsername(),
            "role",              user.getRole().name(),
            "memberSince",       user.getCreatedAt().toString(),
            "usage", Map.of(
                "requestsLast24h",  requestsToday,
                "requestsLastHour", requestsLastHour,
                "tokensLast24h",    tokensToday != null ? tokensToday : 0
            )
        ));
    }

    @GetMapping("/me/api-keys")
    @Operation(
        summary = "Read-only view of your own API keys and their usage",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<List<ApiKeyUsageResponse>> myApiKeys(@AuthenticationPrincipal String username) {
        List<ApiKeyUsageResponse> keys = apiKeyService.listForUser(username).stream()
            .map(k -> new ApiKeyUsageResponse(
                k.getId(), k.getName(), k.getKeyPrefix(), k.getTier().name(), k.getStatus().name(),
                k.getRequestsPerDay(), k.getMaxTokensPerRequest(),
                k.getCreatedAt().toString(),
                k.getExpiresAt() != null ? k.getExpiresAt().toString() : null,
                k.getLastUsedAt() != null ? k.getLastUsedAt().toString() : null,
                auditLogRepository.countByApiKeyId(k.getId()),
                orZero(auditLogRepository.sumTokensByApiKeyId(k.getId()))
            ))
            .toList();
        return ResponseEntity.ok(keys);
    }

    @PostMapping("/me/api-keys")
    @Operation(
        summary = "Self-service: issue your own TRIAL-tier API key — no admin required",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<CreateApiKeyResponse> createMyApiKey(@AuthenticationPrincipal String username) {
        GatewayUser user = userRepository.findByUsername(username).orElseThrow();

        boolean alreadyHasSelfServiceKey = apiKeyService.listForUser(username).stream()
            .anyMatch(k -> SELF_SERVICE_MARKER.equals(k.getCreatedByAdmin()) && k.getStatus() == ApiKey.Status.ACTIVE);
        if (alreadyHasSelfServiceKey) {
            throw new GatewayException(
                "You already have a self-service API key — see GET /api/v1/users/me/api-keys, "
                    + "or ask an admin to issue additional keys.",
                HttpStatus.BAD_REQUEST);
        }

        String orgId = user.getOrganizationId();
        if (orgId == null) {
            // Every ApiKey requires an organization — auto-provision a personal one for
            // self-registered users instead of forcing them through an admin-run org flow.
            Organization org = organizationService.create("personal-" + username);
            organizationService.addMember(org.getId(), username, null); // existing user — password untouched
            orgId = org.getId();
        }

        ApiKeyService.CreatedKey created = apiKeyService.create(
            orgId, username, ApiKey.Tier.TRIAL, "default", SELF_SERVICE_MARKER, null, null, null);
        return ResponseEntity.ok(CreateApiKeyResponse.from(created));
    }

    private static long orZero(Long value) {
        return value != null ? value : 0L;
    }

    public record ApiKeyUsageResponse(
        String id, String name, String keyPrefix, String tier, String status,
        int requestsPerDay, int maxTokensPerRequest,
        String createdAt, String expiresAt, String lastUsedAt,
        long totalRequests, long totalTokens
    ) {}
}

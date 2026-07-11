package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Endpoints any authenticated user can call to see their own usage.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User")
public class UserController {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final ApiKeyService apiKeyService;

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
        summary = "Read-only view of your own API keys and their usage — keys are issued by an admin, not self-service",
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

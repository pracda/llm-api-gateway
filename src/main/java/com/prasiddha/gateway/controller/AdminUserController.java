package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.model.response.ApiKeyResponse;
import com.prasiddha.gateway.model.response.SecurityAlertResponse;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.ThreatDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-user lockout control, evidence trail, and manual account block —
 * everything scoped to one gateway account (path is always {username}, not
 * a user id). All endpoints require ROLE_ADMIN — enforced by @PreAuthorize.
 *
 * Endpoints:
 *   POST /api/v1/admin/users/{username}/unlock   — clear an auto-lockout
 *   GET  /api/v1/admin/users/{username}/activity — evidence trail
 *   POST /api/v1/admin/users/{username}/block    — permanent manual block
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminUserController {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final ThreatDetectionService threatDetectionService;
    private final ApiKeyService apiKeyService;

    @PostMapping("/users/{username}/unlock")
    @Operation(
        summary = "Manually clear an auto-lockout for a user (path is username, not user id)",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<?> unlockUser(@PathVariable String username) {
        threatDetectionService.unlock(username);
        return ResponseEntity.ok(Map.of("message", "Unlocked", "username", username));
    }

    @GetMapping("/users/{username}/activity")
    @Operation(
        summary = "Per-user evidence trail — intent breakdown, token/volume trend, alerts, keys, lockout state",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> getUserActivity(@PathVariable String username) {
        GatewayUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> new GatewayException("User not found: " + username, HttpStatus.NOT_FOUND));

        Instant now = Instant.now();
        Instant startOfToday = LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant since24h = now.minusSeconds(86400);
        Instant since7d  = now.minusSeconds(7 * 86400L);

        Map<String, Long> intentBreakdown = new LinkedHashMap<>();
        for (AuditLog.IntentClassification c : AuditLog.IntentClassification.values()) {
            intentBreakdown.put(c.name(), 0L);
        }
        for (Object[] row : auditLogRepository.countByIntentClassificationForUser(username, since7d)) {
            intentBreakdown.put(((AuditLog.IntentClassification) row[0]).name(), (Long) row[1]);
        }

        Double avgJailbreak = auditLogRepository.avgJailbreakScoreForUser(username, since7d);
        Long tokensLast24h  = auditLogRepository.sumTokensByUserAndPeriod(username, since24h);

        // Behavioral baseline — computed on read from existing aggregates, no stored state, no scheduled job.
        long requestsToday   = auditLogRepository.countByUserIdAndCreatedAtAfter(username, startOfToday);
        long requestsLast7d  = auditLogRepository.countByUserIdAndCreatedAtAfter(username, since7d);
        double trailingAvgPerDay = Math.max(requestsLast7d - requestsToday, 0) / 6.0;
        boolean volumeDeviation = trailingAvgPerDay > 0 && requestsToday > trailingAvgPerDay * 3;
        String volumeDeviationReason = volumeDeviation
            ? String.format("Today's volume (%d) is %.1fx the trailing 6-day average (%.1f/day)",
                requestsToday, requestsToday / trailingAvgPerDay, trailingAvgPerDay)
            : null;

        boolean locked = threatDetectionService.isLocked(username);

        List<SecurityAlertResponse> recentAlerts = securityAlertRepository
            .findTop20ByUsernameOrderByCreatedAtDesc(username)
            .stream().map(SecurityAlertResponse::from).toList();

        List<ApiKeyResponse> apiKeys = apiKeyService.listForUser(username)
            .stream().map(ApiKeyResponse::from).toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("username", username);
        result.put("enabled", user.isEnabled());
        result.put("locked", locked);
        result.put("lockoutRemainingSeconds", locked ? threatDetectionService.lockoutRemainingSeconds(username) : 0);
        result.put("intentBreakdownLast7d", intentBreakdown);
        result.put("avgJailbreakScoreLast7d", avgJailbreak != null ? Math.round(avgJailbreak) : 0);
        result.put("tokensLast24h", tokensLast24h != null ? tokensLast24h : 0);
        result.put("requestsToday", requestsToday);
        result.put("trailingAvgRequestsPerDay", Math.round(trailingAvgPerDay * 10.0) / 10.0);
        result.put("volumeDeviationDetected", volumeDeviation);
        result.put("volumeDeviationReason", volumeDeviationReason);
        result.put("recentAlerts", recentAlerts);
        result.put("apiKeys", apiKeys);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/users/{username}/block")
    @Operation(
        summary = "Permanently block a user — disables the account and revokes all its API keys " +
                  "(distinct from the temporary auto-lockout)",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<?> blockUser(
        @PathVariable String username, @AuthenticationPrincipal String adminUsername
    ) {
        GatewayUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> new GatewayException("User not found: " + username, HttpStatus.NOT_FOUND));

        user.setEnabled(false);
        userRepository.save(user);

        int revokedCount = 0;
        for (ApiKey key : apiKeyService.listForUser(username)) {
            if (key.getStatus() == ApiKey.Status.ACTIVE || key.getStatus() == ApiKey.Status.SUSPENDED) {
                apiKeyService.revoke(key.getId());
                revokedCount++;
            }
        }

        threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.USER_MANUALLY_BLOCKED,
            "Account manually blocked by admin '" + adminUsername + "' — " + revokedCount + " API key(s) revoked");

        return ResponseEntity.ok(Map.of(
            "message", "User blocked", "username", username, "apiKeysRevoked", revokedCount
        ));
    }
}

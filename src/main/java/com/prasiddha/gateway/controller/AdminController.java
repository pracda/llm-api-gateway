package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.OrganizationService;
import com.prasiddha.gateway.service.SseEmitterRegistry;
import com.prasiddha.gateway.service.ThreatDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
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
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Admin-only endpoints for audit log queries and usage statistics.
 * All endpoints require ROLE_ADMIN — enforced by @PreAuthorize.
 *
 * Endpoints:
 *   GET /api/v1/admin/logs          — paginated audit log
 *   GET /api/v1/admin/logs/{userId} — logs for a specific user
 *   GET /api/v1/admin/stats         — usage dashboard
 *   GET /api/v1/admin/stats/today   — today's summary
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminController {

    private final AuditLogRepository auditLogRepository;
    private final OrganizationService organizationService;
    private final ApiKeyService apiKeyService;
    private final SecurityAlertRepository securityAlertRepository;
    private final ThreatDetectionService threatDetectionService;
    private final SseEmitterRegistry sseEmitterRegistry;

    // ── GET /api/v1/admin/logs ────────────────────────────────────────────

    @GetMapping("/logs")
    @Operation(
        summary = "Paginated audit log — all users",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Page<AuditLogResponse>> getLogs(
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "20") int size,
        @RequestParam(required = false)    String outcome
    ) {
        PageRequest pageable = PageRequest.of(
            page, Math.min(size, 100),
            Sort.by(Sort.Direction.DESC, "createdAt")
        );

        Page<AuditLog> logs = (outcome != null)
            ? auditLogRepository.findByOutcome(AuditLog.Outcome.valueOf(outcome.toUpperCase()), pageable)
            : auditLogRepository.findAll(pageable);

        return ResponseEntity.ok(logs.map(AuditLogResponse::from));
    }

    // ── GET /api/v1/admin/logs/{userId} ───────────────────────────────────

    @GetMapping("/logs/{userId}")
    @Operation(
        summary = "Audit log for a specific user",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Page<AuditLogResponse>> getUserLogs(
        @PathVariable String userId,
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "20") int size
    ) {
        PageRequest pageable = PageRequest.of(
            page, Math.min(size, 100),
            Sort.by(Sort.Direction.DESC, "createdAt")
        );
        return ResponseEntity.ok(
            auditLogRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable)
                .map(AuditLogResponse::from)
        );
    }

    // ── GET /api/v1/admin/stats ───────────────────────────────────────────

    @GetMapping("/stats")
    @Operation(
        summary = "Overall usage statistics",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> getStats() {
        Instant last24h = Instant.now().minusSeconds(86400);
        Instant last1h  = Instant.now().minusSeconds(3600);

        long totalRequests    = auditLogRepository.count();
        long requestsLast24h  = auditLogRepository.countByCreatedAtAfter(last24h);
        long requestsLastHour = auditLogRepository.countByCreatedAtAfter(last1h);

        // Outcome breakdown (last 24h)
        long successCount    = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.SUCCESS,                  last24h);
        long injectionBlocks = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.BLOCKED_INPUT_INJECTION,  last24h);
        long outputBlocks    = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.BLOCKED_OUTPUT_UNSAFE,    last24h);
        long rateLimitBlocks = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.BLOCKED_RATE_LIMIT,       last24h);
        long errorCount      = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.ERROR,                    last24h);

        // Provider breakdown (last 24h)
        List<Object[]> providerStats = auditLogRepository.countByProviderLast24h(last24h);
        Map<String, Long> byProvider = providerStats.stream()
            .collect(Collectors.toMap(
                r -> (String) r[0],
                r -> (Long)   r[1],
                (a, b) -> a,
                LinkedHashMap::new
            ));

        // Token usage (last 24h)
        Long totalTokens = auditLogRepository.sumTotalTokensAfter(last24h);

        // Average latency (last 24h)
        Double avgLatency = auditLogRepository.avgLatencyAfter(last24h);

        // Recent blocked requests (last 10)
        List<AuditLogResponse> recentBlocked = auditLogRepository
            .findTop10ByOutcomeNotOrderByCreatedAtDesc(AuditLog.Outcome.SUCCESS)
            .stream().map(AuditLogResponse::from).toList();

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalRequests",     totalRequests);
        stats.put("last24Hours", Map.of(
            "total",            requestsLast24h,
            "lastHour",         requestsLastHour,
            "success",          successCount,
            "blockedInjection", injectionBlocks,
            "blockedOutput",    outputBlocks,
            "blockedRateLimit", rateLimitBlocks,
            "errors",           errorCount
        ));
        stats.put("byProvider",         byProvider);
        stats.put("totalTokensLast24h", totalTokens != null ? totalTokens : 0);
        stats.put("avgLatencyMs",       avgLatency  != null ? Math.round(avgLatency) : 0);
        stats.put("recentBlocked",      recentBlocked);

        return ResponseEntity.ok(stats);
    }

    // ── GET /api/v1/admin/stats/today ─────────────────────────────────────

    @GetMapping("/stats/today")
    @Operation(
        summary = "Today's request summary",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> getTodayStats() {
        Instant startOfDay = LocalDate.now(ZoneOffset.UTC)
            .atStartOfDay(ZoneOffset.UTC).toInstant();

        long total       = auditLogRepository.countByCreatedAtAfter(startOfDay);
        long success     = auditLogRepository.countByOutcomeAndCreatedAtAfter(AuditLog.Outcome.SUCCESS,                 startOfDay);
        long blocked     = total - success;
        Long tokens      = auditLogRepository.sumTotalTokensAfter(startOfDay);
        Double avgMs     = auditLogRepository.avgLatencyAfter(startOfDay);

        return ResponseEntity.ok(Map.of(
            "date",          LocalDate.now(ZoneOffset.UTC).toString(),
            "totalRequests", total,
            "successful",    success,
            "blocked",       blocked,
            "totalTokens",   tokens   != null ? tokens : 0,
            "avgLatencyMs",  avgMs    != null ? Math.round(avgMs) : 0
        ));
    }

    // ── GET /api/v1/admin/users ───────────────────────────────────────────

    @GetMapping("/users")
    @Operation(
        summary = "Top users by request count (last 24h)",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<List<Map<String, Object>>> getTopUsers() {
        Instant last24h = Instant.now().minusSeconds(86400);
        List<Object[]> results = auditLogRepository.topUsersByRequestCount(last24h);

        List<Map<String, Object>> topUsers = results.stream()
            .map(r -> Map.<String, Object>of(
                "userId",   r[0],
                "requests", r[1]
            ))
            .toList();

        return ResponseEntity.ok(topUsers);
    }

    // ── Organizations ──────────────────────────────────────────────────────

    @PostMapping("/organizations")
    @Operation(summary = "Create an organization", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<OrganizationResponse> createOrganization(@Valid @RequestBody CreateOrgRequest req) {
        Organization org = organizationService.create(req.name());
        return ResponseEntity.ok(OrganizationResponse.from(org));
    }

    @GetMapping("/organizations")
    @Operation(summary = "List organizations", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<List<OrganizationResponse>> listOrganizations() {
        return ResponseEntity.ok(
            organizationService.listAll().stream().map(OrganizationResponse::from).toList()
        );
    }

    @GetMapping("/organizations/{id}")
    @Operation(summary = "Organization detail — members and keys", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Map<String, Object>> getOrganization(@PathVariable String id) {
        Organization org = organizationService.get(id);
        List<ApiKeyResponse> keys = apiKeyService.listForOrg(id).stream().map(ApiKeyResponse::from).toList();
        return ResponseEntity.ok(Map.of(
            "organization", OrganizationResponse.from(org),
            "apiKeys",      keys
        ));
    }

    @PostMapping("/organizations/{id}/members")
    @Operation(summary = "Add an existing user to an organization", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> addMember(@PathVariable String id, @Valid @RequestBody AddMemberRequest req) {
        organizationService.addMember(id, req.username());
        return ResponseEntity.ok(Map.of("message", "Added", "username", req.username(), "organizationId", id));
    }

    // ── API keys ─────────────────────────────────────────────────────────

    @PostMapping("/organizations/{id}/api-keys")
    @Operation(summary = "Issue an API key for an organization member", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
        @PathVariable String id,
        @Valid @RequestBody CreateApiKeyRequest req,
        @AuthenticationPrincipal String adminUsername
    ) {
        ApiKeyService.CreatedKey created = apiKeyService.create(
            id, req.username(), req.tier(), req.name(), adminUsername,
            req.requestsPerDay(), req.maxTokensPerRequest(), req.expiresInDays()
        );
        return ResponseEntity.ok(CreateApiKeyResponse.from(created));
    }

    @PostMapping("/api-keys/{id}/suspend")
    @Operation(summary = "Temporarily suspend an API key", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiKeyResponse> suspendApiKey(@PathVariable String id) {
        return ResponseEntity.ok(ApiKeyResponse.from(apiKeyService.suspend(id)));
    }

    @PostMapping("/api-keys/{id}/resume")
    @Operation(summary = "Resume a suspended API key", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiKeyResponse> resumeApiKey(@PathVariable String id) {
        return ResponseEntity.ok(ApiKeyResponse.from(apiKeyService.resume(id)));
    }

    @DeleteMapping("/api-keys/{id}")
    @Operation(summary = "Permanently revoke an API key", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiKeyResponse> revokeApiKey(@PathVariable String id) {
        return ResponseEntity.ok(ApiKeyResponse.from(apiKeyService.revoke(id)));
    }

    // ── Security alerts ──────────────────────────────────────────────────

    @GetMapping("/alerts")
    @Operation(summary = "Paginated security alerts", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Page<SecurityAlertResponse>> getAlerts(
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "20") int size,
        @RequestParam(required = false)    Boolean acknowledged,
        @RequestParam(required = false)    String severity
    ) {
        PageRequest pageable = PageRequest.of(page, Math.min(size, 100), Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<SecurityAlert> alerts;
        if (acknowledged != null && severity != null) {
            alerts = securityAlertRepository.findByAcknowledgedAndSeverity(
                acknowledged, SecurityAlert.Severity.valueOf(severity.toUpperCase()), pageable);
        } else if (acknowledged != null) {
            alerts = securityAlertRepository.findByAcknowledged(acknowledged, pageable);
        } else if (severity != null) {
            alerts = securityAlertRepository.findBySeverity(SecurityAlert.Severity.valueOf(severity.toUpperCase()), pageable);
        } else {
            alerts = securityAlertRepository.findAll(pageable);
        }

        return ResponseEntity.ok(alerts.map(SecurityAlertResponse::from));
    }

    @PostMapping("/alerts/{id}/acknowledge")
    @Operation(summary = "Acknowledge a security alert", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<SecurityAlertResponse> acknowledgeAlert(
        @PathVariable String id, @AuthenticationPrincipal String adminUsername
    ) {
        SecurityAlert alert = securityAlertRepository.findById(id)
            .orElseThrow(() -> new GatewayException("Alert not found: " + id, HttpStatus.NOT_FOUND));
        alert.setAcknowledged(true);
        alert.setAcknowledgedBy(adminUsername);
        alert.setAcknowledgedAt(Instant.now());
        return ResponseEntity.ok(SecurityAlertResponse.from(securityAlertRepository.save(alert)));
    }

    // ── Lockouts & IP blocklist ──────────────────────────────────────────

    @PostMapping("/users/{username}/unlock")
    @Operation(
        summary = "Manually clear an auto-lockout for a user (path is username, not user id)",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<?> unlockUser(@PathVariable String username) {
        threatDetectionService.unlock(username);
        return ResponseEntity.ok(Map.of("message", "Unlocked", "username", username));
    }

    @GetMapping("/ip-blocks")
    @Operation(summary = "List blocked IP addresses", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Set<String>> listIpBlocks() {
        return ResponseEntity.ok(threatDetectionService.listBlockedIps());
    }

    @PostMapping("/ip-blocks")
    @Operation(summary = "Block an IP address", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> blockIp(@Valid @RequestBody BlockIpRequest req) {
        threatDetectionService.blockIp(req.ip());
        return ResponseEntity.ok(Map.of("message", "Blocked", "ip", req.ip()));
    }

    @DeleteMapping("/ip-blocks/{ip}")
    @Operation(summary = "Unblock an IP address", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> unblockIp(@PathVariable String ip) {
        threatDetectionService.unblockIp(ip);
        return ResponseEntity.ok(Map.of("message", "Unblocked", "ip", ip));
    }

    // ── Live stream ──────────────────────────────────────────────────────

    @GetMapping(value = "/stream", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(
        summary = "Live SSE feed of audit events and security alerts for the ops dashboard",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public org.springframework.web.servlet.mvc.method.annotation.SseEmitter stream() {
        return sseEmitterRegistry.register();
    }

    // ── Risk rankings & attack timeline ──────────────────────────────────

    @GetMapping("/risk-rankings")
    @Operation(summary = "Per-user risk score (0-100), highest first", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<List<Map<String, Object>>> getRiskRankings(
        @RequestParam(defaultValue = "10") int limit
    ) {
        Instant since = Instant.now().minusSeconds(86400);
        Map<String, Integer> scores = new LinkedHashMap<>();
        Map<String, List<String>> reasons = new LinkedHashMap<>();

        for (SecurityAlert alert : securityAlertRepository.findByCreatedAtAfterAndUsernameIsNotNull(since)) {
            scores.merge(alert.getUsername(), severityWeight(alert.getSeverity()), Integer::sum);
            reasons.computeIfAbsent(alert.getUsername(), k -> new java.util.ArrayList<>())
                .add(alert.getType().name());
        }

        for (Object[] row : auditLogRepository.countBlockedByUserLast24h(since)) {
            String userId = (String) row[0];
            long count = (Long) row[1];
            scores.merge(userId, (int) Math.min(count * 5, 40), Integer::sum);
            reasons.computeIfAbsent(userId, k -> new java.util.ArrayList<>())
                .add(count + " blocked requests today");
        }

        List<Map<String, Object>> ranked = scores.entrySet().stream()
            .map(e -> {
                String username = e.getKey();
                int score = Math.min(e.getValue(), 100);
                long distinctIps = auditLogRepository.countDistinctIpsByUserAndPeriod(username, since);
                List<String> reasonList = new java.util.ArrayList<>(reasons.getOrDefault(username, List.of()));
                if (distinctIps > 1) reasonList.add(distinctIps + " distinct IPs");
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("username", username);
                entry.put("score", score);
                entry.put("severity", score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 15 ? "MEDIUM" : "LOW");
                entry.put("reasons", reasonList);
                entry.put("locked", threatDetectionService.isLocked(username));
                return entry;
            })
            .sorted((a, b) -> Integer.compare((int) b.get("score"), (int) a.get("score")))
            .limit(limit)
            .toList();

        return ResponseEntity.ok(ranked);
    }

    @GetMapping("/attack-timeline")
    @Operation(summary = "Hourly-bucketed blocked-request counts, last 24h", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<int[]> getAttackTimeline() {
        Instant since = Instant.now().minusSeconds(86400);
        int[] buckets = new int[24];
        for (Instant ts : auditLogRepository.findBlockedTimestampsAfter(since)) {
            long hoursAgo = java.time.Duration.between(ts, Instant.now()).toHours();
            int bucket = (int) Math.min(Math.max(23 - hoursAgo, 0), 23);
            buckets[bucket]++;
        }
        return ResponseEntity.ok(buckets);
    }

    private int severityWeight(SecurityAlert.Severity severity) {
        return switch (severity) {
            case HIGH -> 40;
            case MEDIUM -> 20;
            case LOW -> 5;
        };
    }

    public record BlockIpRequest(@NotBlank String ip) {}

    public record SecurityAlertResponse(
        String id, String username, String type, String severity, String message,
        boolean autoLockApplied, boolean acknowledged, String acknowledgedBy, String acknowledgedAt, String createdAt
    ) {
        static SecurityAlertResponse from(SecurityAlert a) {
            return new SecurityAlertResponse(
                a.getId(), a.getUsername(), a.getType().name(), a.getSeverity().name(), a.getMessage(),
                a.isAutoLockApplied(), a.isAcknowledged(), a.getAcknowledgedBy(),
                a.getAcknowledgedAt() != null ? a.getAcknowledgedAt().toString() : null,
                a.getCreatedAt().toString()
            );
        }
    }

    // ── Response / request DTOs ────────────────────────────────────────────

    public record CreateOrgRequest(@NotBlank String name) {}

    public record AddMemberRequest(@NotBlank String username) {}

    public record CreateApiKeyRequest(
        @NotBlank String username,
        @NotNull ApiKey.Tier tier,
        @NotBlank String name,
        Integer requestsPerDay,
        Integer maxTokensPerRequest,
        Integer expiresInDays
    ) {}

    public record OrganizationResponse(String id, String name, String createdAt) {
        static OrganizationResponse from(Organization o) {
            return new OrganizationResponse(o.getId(), o.getName(), o.getCreatedAt().toString());
        }
    }

    public record ApiKeyResponse(
        String id, String organizationId, String username, String name, String keyPrefix,
        String tier, int requestsPerDay, int maxTokensPerRequest, String status,
        String createdAt, String expiresAt, String lastUsedAt, String createdByAdmin
    ) {
        static ApiKeyResponse from(ApiKey k) {
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

    public record CreateApiKeyResponse(ApiKeyResponse key, String apiKey) {
        static CreateApiKeyResponse from(ApiKeyService.CreatedKey created) {
            return new CreateApiKeyResponse(ApiKeyResponse.from(created.apiKey()), created.rawKey());
        }
    }

    // ── Response DTO ──────────────────────────────────────────────────────

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
        String createdAt
    ) {
        static AuditLogResponse from(AuditLog log) {
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
                log.getCreatedAt().toString()
            );
        }
    }
}

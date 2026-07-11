package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.OrganizationService;
import com.prasiddha.gateway.service.ReportPdfService;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
    private final UserRepository userRepository;
    private final ReportPdfService reportPdfService;

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
    @Operation(
        summary = "Add a user to an organization — auto-provisions the GatewayUser account if it doesn't exist yet",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<?> addMember(@PathVariable String id, @Valid @RequestBody AddMemberRequest req) {
        OrganizationService.AddMemberResult result = organizationService.addMember(id, req.username(), req.password());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Added");
        body.put("username", req.username());
        body.put("organizationId", id);
        body.put("accountCreated", result.created());
        if (result.generatedPassword() != null) {
            body.put("generatedPassword", result.generatedPassword());
        }
        return ResponseEntity.ok(body);
    }

    @GetMapping("/organizations/{id}/logs")
    @Operation(summary = "Paginated audit log scoped to this organization's members", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Page<AuditLogResponse>> getOrganizationLogs(
        @PathVariable String id,
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "20") int size
    ) {
        organizationService.get(id); // 404 if the org doesn't exist
        PageRequest pageable = PageRequest.of(
            page, Math.min(size, 100), Sort.by(Sort.Direction.DESC, "createdAt"));
        return ResponseEntity.ok(
            auditLogRepository.findByOrganizationMembers(id, pageable).map(AuditLogResponse::from)
        );
    }

    @GetMapping("/organizations/{id}/trend")
    @Operation(
        summary = "Day-bucketed request/block/token trend for this organization, plus top alert types",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> getOrganizationTrend(
        @PathVariable String id,
        @RequestParam(defaultValue = "7") int days
    ) {
        organizationService.get(id);
        int clampedDays = Math.max(1, Math.min(days, 30));
        Instant since = Instant.now().minusSeconds(clampedDays * 86400L);

        Map<LocalDate, int[]> dayTotals = new LinkedHashMap<>(); // [totalRequests, blocked, totalTokens]
        Map<LocalDate, Map<String, Integer>> dayIntent = new LinkedHashMap<>();

        for (AuditLog log : auditLogRepository.findByOrganizationMembersSince(id, since)) {
            LocalDate day = log.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate();
            int[] totals = dayTotals.computeIfAbsent(day, d -> new int[3]);
            totals[0]++;
            if (log.getOutcome() != AuditLog.Outcome.SUCCESS) totals[1]++;
            totals[2] += log.getPromptTokens() + log.getCompletionTokens();
            dayIntent.computeIfAbsent(day, d -> new LinkedHashMap<>())
                .merge(log.getIntentClassification().name(), 1, Integer::sum);
        }

        List<Map<String, Object>> dayList = new java.util.ArrayList<>();
        for (int i = clampedDays - 1; i >= 0; i--) {
            LocalDate day = LocalDate.now(ZoneOffset.UTC).minusDays(i);
            int[] totals = dayTotals.getOrDefault(day, new int[3]);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("date", day.toString());
            entry.put("totalRequests", totals[0]);
            entry.put("blocked", totals[1]);
            entry.put("totalTokens", totals[2]);
            entry.put("intentBreakdown", dayIntent.getOrDefault(day, Map.of()));
            dayList.add(entry);
        }

        Map<SecurityAlert.Type, Long> counts = securityAlertRepository
            .findByOrganizationMembersSince(id, since).stream()
            .collect(Collectors.groupingBy(SecurityAlert::getType, Collectors.counting()));
        List<Map<String, Object>> topAlertTypes = counts.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .limit(5)
            .map(e -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type", e.getKey().name());
                m.put("label", e.getKey().friendlyLabel());
                m.put("count", e.getValue());
                return m;
            })
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("organizationId", id);
        result.put("days", dayList);
        result.put("topAlertTypes", topAlertTypes);
        return ResponseEntity.ok(result);
    }

    @GetMapping(value = "/organizations/{id}/report", produces = "application/pdf")
    @Operation(
        summary = "Download a PDF activity report (weekly or monthly) covering every member of this organization",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<byte[]> getOrganizationReport(
        @PathVariable String id,
        @RequestParam(defaultValue = "weekly") String period
    ) {
        Organization org = organizationService.get(id);
        boolean monthly = "monthly".equalsIgnoreCase(period);
        int days = monthly ? 30 : 7;
        Instant periodStart = Instant.now().minusSeconds(days * 86400L);
        Instant periodEnd = Instant.now();

        // [totalRequests, blocked, totalTokens, suspicious, malicious, alertCount] per username
        Map<String, long[]> counts = new LinkedHashMap<>();
        Map<String, Double> avgScores = new LinkedHashMap<>();
        for (GatewayUser member : userRepository.findByOrganizationId(id)) {
            counts.put(member.getUsername(), new long[6]);
        }

        for (Object[] row : auditLogRepository.memberStatsForOrganization(id, periodStart)) {
            String username = (String) row[0];
            long[] c = counts.computeIfAbsent(username, k -> new long[6]);
            c[0] = (Long) row[1];
            c[1] = (Long) row[2];
            c[2] = (Long) row[3];
            c[3] = (Long) row[4];
            c[4] = (Long) row[5];
            avgScores.put(username, row[6] != null ? (Double) row[6] : 0.0);
        }

        for (Object[] row : securityAlertRepository.countAlertsByMemberForOrganization(id, periodStart)) {
            String username = (String) row[0];
            counts.computeIfAbsent(username, k -> new long[6])[5] = (Long) row[1];
        }

        List<ReportPdfService.MemberRow> reportRows = counts.entrySet().stream()
            .map(e -> new ReportPdfService.MemberRow(
                e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[2], e.getValue()[3], e.getValue()[4],
                e.getValue()[5], avgScores.getOrDefault(e.getKey(), 0.0)
            ))
            .sorted((a, b) -> Long.compare(b.totalRequests(), a.totalRequests()))
            .toList();

        byte[] pdf = reportPdfService.generateOrganizationReport(
            org.getName(), monthly ? "Monthly report" : "Weekly report", periodStart, periodEnd, reportRows
        );

        String safeName = org.getName().replaceAll("[^a-zA-Z0-9-]", "_");
        String filename = "gateway-report-" + safeName + "-" + period + ".pdf";

        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
            .contentType(MediaType.APPLICATION_PDF)
            .body(pdf);
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

    // ── Per-user evidence trail & manual block ──────────────────────────

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
                .add(alert.getType().friendlyLabel());
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
        String id, String username, String type, String label, String severity, String message,
        boolean autoLockApplied, boolean acknowledged, String acknowledgedBy, String acknowledgedAt, String createdAt
    ) {
        static SecurityAlertResponse from(SecurityAlert a) {
            return new SecurityAlertResponse(
                a.getId(), a.getUsername(), a.getType().name(), a.getType().friendlyLabel(),
                a.getSeverity().name(), a.getMessage(),
                a.isAutoLockApplied(), a.isAcknowledged(), a.getAcknowledgedBy(),
                a.getAcknowledgedAt() != null ? a.getAcknowledgedAt().toString() : null,
                a.getCreatedAt().toString()
            );
        }
    }

    // ── Response / request DTOs ────────────────────────────────────────────

    public record CreateOrgRequest(@NotBlank String name) {}

    public record AddMemberRequest(@NotBlank String username, String password) {}

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
        String intentClassification,
        String intentReason,
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
                log.getIntentClassification().name(),
                log.getIntentReason(),
                log.getCreatedAt().toString()
            );
        }
    }
}

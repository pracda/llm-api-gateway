package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.model.response.AuditLogResponse;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.service.SseEmitterRegistry;
import com.prasiddha.gateway.service.ThreatDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Admin dashboard overview: audit log queries, usage statistics, the live
 * SSE feed, and risk/attack visibility across the whole gateway (not scoped
 * to one organization or user — see AdminOrganizationController,
 * AdminUserController, AdminAlertController, and AdminReportController for
 * those). All endpoints require ROLE_ADMIN — enforced by @PreAuthorize.
 *
 * Endpoints:
 *   GET /api/v1/admin/logs            — paginated audit log
 *   GET /api/v1/admin/logs/{userId}   — logs for a specific user
 *   GET /api/v1/admin/stats           — usage dashboard
 *   GET /api/v1/admin/stats/today     — today's summary
 *   GET /api/v1/admin/users           — top users by request count
 *   GET /api/v1/admin/stream          — live SSE feed
 *   GET /api/v1/admin/risk-rankings   — per-user risk score
 *   GET /api/v1/admin/attack-timeline — hourly blocked-request counts
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminController {

    private final AuditLogRepository auditLogRepository;
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

    // ── Live stream ──────────────────────────────────────────────────────

    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(
        summary = "Live SSE feed of audit events and security alerts for the ops dashboard",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public SseEmitter stream() {
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
            reasons.computeIfAbsent(alert.getUsername(), k -> new ArrayList<>())
                .add(alert.getType().friendlyLabel());
        }

        for (Object[] row : auditLogRepository.countBlockedByUserLast24h(since)) {
            String userId = (String) row[0];
            long count = (Long) row[1];
            scores.merge(userId, (int) Math.min(count * 5, 40), Integer::sum);
            reasons.computeIfAbsent(userId, k -> new ArrayList<>())
                .add(count + " blocked requests today");
        }

        List<Map<String, Object>> ranked = scores.entrySet().stream()
            .map(e -> {
                String username = e.getKey();
                int score = Math.min(e.getValue(), 100);
                long distinctIps = auditLogRepository.countDistinctIpsByUserAndPeriod(username, since);
                List<String> reasonList = new ArrayList<>(reasons.getOrDefault(username, List.of()));
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
            long hoursAgo = Duration.between(ts, Instant.now()).toHours();
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
}

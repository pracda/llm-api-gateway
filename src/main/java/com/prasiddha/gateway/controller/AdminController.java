package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.repository.AuditLogRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
                log.getCreatedAt().toString()
            );
        }
    }
}

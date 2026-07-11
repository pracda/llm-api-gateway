package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    // ── Paginated queries ─────────────────────────────────────────────────

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(String userId, Pageable pageable);

    Page<AuditLog> findByOutcome(AuditLog.Outcome outcome, Pageable pageable);

    List<AuditLog> findTop10ByOutcomeNotOrderByCreatedAtDesc(AuditLog.Outcome outcome);

    // ── Count queries ─────────────────────────────────────────────────────

    long countByCreatedAtAfter(Instant since);

    long countByOutcomeAndCreatedAtAfter(AuditLog.Outcome outcome, Instant since);

    long countByUserIdAndCreatedAtAfter(String userId, Instant since);

    // ── Aggregation queries ───────────────────────────────────────────────

    @Query("SELECT SUM(a.promptTokens + a.completionTokens) FROM AuditLog a WHERE a.createdAt > :since")
    Long sumTotalTokensAfter(@Param("since") Instant since);

    @Query("SELECT AVG(a.latencyMs) FROM AuditLog a WHERE a.createdAt > :since AND a.outcome = 'SUCCESS'")
    Double avgLatencyAfter(@Param("since") Instant since);

    @Query("SELECT a.provider, COUNT(a) FROM AuditLog a WHERE a.createdAt > :since GROUP BY a.provider")
    List<Object[]> countByProviderLast24h(@Param("since") Instant since);

    @Query("SELECT a.userId, COUNT(a) as cnt FROM AuditLog a WHERE a.createdAt > :since GROUP BY a.userId ORDER BY cnt DESC")
    List<Object[]> topUsersByRequestCount(@Param("since") Instant since);

    @Query("SELECT SUM(a.promptTokens + a.completionTokens) FROM AuditLog a WHERE a.userId = :userId AND a.createdAt > :since")
    Long sumTokensByUserAndPeriod(@Param("userId") String userId, @Param("since") Instant since);

    long countByApiKeyId(String apiKeyId);

    @Query("SELECT SUM(a.promptTokens + a.completionTokens) FROM AuditLog a WHERE a.apiKeyId = :apiKeyId")
    Long sumTokensByApiKeyId(@Param("apiKeyId") String apiKeyId);

    @Query("SELECT a.userId, COUNT(a) FROM AuditLog a WHERE a.createdAt > :since " +
           "AND a.outcome IN ('BLOCKED_INPUT_INJECTION', 'BLOCKED_OUTPUT_UNSAFE') GROUP BY a.userId")
    List<Object[]> countBlockedByUserLast24h(@Param("since") Instant since);

    @Query("SELECT COUNT(DISTINCT a.ipAddress) FROM AuditLog a WHERE a.userId = :userId AND a.createdAt > :since")
    long countDistinctIpsByUserAndPeriod(@Param("userId") String userId, @Param("since") Instant since);

    @Query("SELECT a.createdAt FROM AuditLog a WHERE a.createdAt > :since AND a.outcome <> 'SUCCESS' ORDER BY a.createdAt")
    List<Instant> findBlockedTimestampsAfter(@Param("since") Instant since);

    // ── Per-user evidence trail (intent classification + behavioral baseline) ──

    @Query("SELECT a.intentClassification, COUNT(a) FROM AuditLog a " +
           "WHERE a.userId = :userId AND a.createdAt > :since GROUP BY a.intentClassification")
    List<Object[]> countByIntentClassificationForUser(@Param("userId") String userId, @Param("since") Instant since);

    @Query("SELECT AVG(a.jailbreakScore) FROM AuditLog a WHERE a.userId = :userId AND a.createdAt > :since")
    Double avgJailbreakScoreForUser(@Param("userId") String userId, @Param("since") Instant since);

    // ── Per-organization views (joins by username, not a JPA relation — GatewayUser.organizationId is a plain column) ──

    @Query("SELECT a FROM AuditLog a WHERE a.createdAt > :since " +
           "AND a.userId IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId)")
    List<AuditLog> findByOrganizationMembersSince(@Param("orgId") String orgId, @Param("since") Instant since);

    @Query(
        value = "SELECT a FROM AuditLog a WHERE a.userId IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId)",
        countQuery = "SELECT COUNT(a) FROM AuditLog a WHERE a.userId IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId)"
    )
    Page<AuditLog> findByOrganizationMembers(@Param("orgId") String orgId, Pageable pageable);

    /**
     * Per-member rollup for the PDF activity report: [userId, totalRequests, blocked,
     * totalTokens, suspiciousCount, maliciousCount, avgJailbreakScore]. Aggregated
     * counts only — never raw prompt/response content (OWASP LLM #06).
     */
    @Query("SELECT a.userId, COUNT(a), " +
           "SUM(CASE WHEN a.outcome <> 'SUCCESS' THEN 1 ELSE 0 END), " +
           "SUM(a.promptTokens + a.completionTokens), " +
           "SUM(CASE WHEN a.intentClassification = 'SUSPICIOUS' THEN 1 ELSE 0 END), " +
           "SUM(CASE WHEN a.intentClassification = 'MALICIOUS' THEN 1 ELSE 0 END), " +
           "AVG(a.jailbreakScore) " +
           "FROM AuditLog a WHERE a.createdAt > :since " +
           "AND a.userId IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId) " +
           "GROUP BY a.userId")
    List<Object[]> memberStatsForOrganization(@Param("orgId") String orgId, @Param("since") Instant since);
}

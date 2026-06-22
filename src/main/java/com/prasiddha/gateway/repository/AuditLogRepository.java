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
}

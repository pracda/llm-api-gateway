package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.time.Instant;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(String userId, Pageable pageable);

    long countByUserIdAndCreatedAtAfter(String userId, Instant since);

    long countByOutcomeAndCreatedAtAfter(AuditLog.Outcome outcome, Instant since);

    @Query("SELECT SUM(a.promptTokens + a.completionTokens) FROM AuditLog a " +
           "WHERE a.userId = :userId AND a.createdAt > :since")
    Long sumTokensByUserAndPeriod(String userId, Instant since);

    List<AuditLog> findTop10ByOrderByCreatedAtDesc();
}

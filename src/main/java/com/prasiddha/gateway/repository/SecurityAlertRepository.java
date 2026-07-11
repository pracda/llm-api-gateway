package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, String> {

    List<SecurityAlert> findByCreatedAtAfterAndUsernameIsNotNull(Instant since);

    Page<SecurityAlert> findByAcknowledged(boolean acknowledged, Pageable pageable);

    Page<SecurityAlert> findBySeverity(SecurityAlert.Severity severity, Pageable pageable);

    Page<SecurityAlert> findByAcknowledgedAndSeverity(
        boolean acknowledged, SecurityAlert.Severity severity, Pageable pageable);

    long countByAcknowledgedFalse();

    long countByUsernameAndAcknowledgedFalse(String username);

    List<SecurityAlert> findTop20ByUsernameOrderByCreatedAtDesc(String username);

    @Query("SELECT s FROM SecurityAlert s WHERE s.createdAt > :since " +
           "AND s.username IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId)")
    List<SecurityAlert> findByOrganizationMembersSince(@Param("orgId") String orgId, @Param("since") Instant since);

    @Query("SELECT s.username, COUNT(s) FROM SecurityAlert s WHERE s.createdAt > :since " +
           "AND s.username IN (SELECT u.username FROM GatewayUser u WHERE u.organizationId = :orgId) " +
           "GROUP BY s.username")
    List<Object[]> countAlertsByMemberForOrganization(@Param("orgId") String orgId, @Param("since") Instant since);
}

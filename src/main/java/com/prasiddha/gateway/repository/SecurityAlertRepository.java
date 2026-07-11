package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

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
}

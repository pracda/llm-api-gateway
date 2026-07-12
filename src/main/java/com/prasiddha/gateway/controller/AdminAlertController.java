package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.model.response.SecurityAlertResponse;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.service.ThreatDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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
import java.util.Map;
import java.util.Set;

/**
 * Security alerts and IP blocklist management — the threat-ops side of the
 * dashboard (not tied to any one organization or user). All endpoints
 * require ROLE_ADMIN — enforced by @PreAuthorize.
 *
 * Endpoints:
 *   GET    /api/v1/admin/alerts                 — paginated security alerts
 *   POST   /api/v1/admin/alerts/{id}/acknowledge — acknowledge an alert
 *   GET    /api/v1/admin/ip-blocks              — list blocked IPs
 *   POST   /api/v1/admin/ip-blocks              — block an IP
 *   DELETE /api/v1/admin/ip-blocks/{ip}         — unblock an IP
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminAlertController {

    private final SecurityAlertRepository securityAlertRepository;
    private final ThreatDetectionService threatDetectionService;

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

    public record BlockIpRequest(@NotBlank String ip) {}
}

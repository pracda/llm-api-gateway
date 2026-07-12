package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.OrganizationService;
import com.prasiddha.gateway.service.ReportPdfService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Downloadable PDF activity reports per organization — the artifact an org
 * admin takes to a compliance/security review. Requires ROLE_ADMIN —
 * enforced by @PreAuthorize.
 *
 * Endpoints:
 *   GET /api/v1/admin/organizations/{id}/report — weekly/monthly PDF report
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminReportController {

    private final OrganizationService organizationService;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final ReportPdfService reportPdfService;

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
}

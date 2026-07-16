package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.model.response.ApiKeyResponse;
import com.prasiddha.gateway.model.response.AuditLogResponse;
import com.prasiddha.gateway.model.response.CreateApiKeyResponse;
import com.prasiddha.gateway.repository.AuditLogRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.OrganizationService;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Organization, member, and API-key lifecycle — everything scoped to one
 * organization. All endpoints require ROLE_ADMIN — enforced by @PreAuthorize.
 *
 * Endpoints:
 *   POST   /api/v1/admin/organizations                    — create an org
 *   GET    /api/v1/admin/organizations                     — list orgs
 *   GET    /api/v1/admin/organizations/{id}                — org detail (members' keys)
 *   POST   /api/v1/admin/organizations/{id}/members        — add/auto-provision a member
 *   GET    /api/v1/admin/organizations/{id}/logs           — audit log scoped to this org
 *   GET    /api/v1/admin/organizations/{id}/trend          — day-bucketed trend + top alert types
 *   POST   /api/v1/admin/organizations/{id}/api-keys       — issue a key
 *   POST   /api/v1/admin/api-keys/{id}/suspend             — suspend a key
 *   POST   /api/v1/admin/api-keys/{id}/resume              — resume a key
 *   DELETE /api/v1/admin/api-keys/{id}                     — revoke a key
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Dashboard")
public class AdminOrganizationController {

    private final OrganizationService organizationService;
    private final ApiKeyService apiKeyService;
    private final AuditLogRepository auditLogRepository;
    private final SecurityAlertRepository securityAlertRepository;

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

        List<Map<String, Object>> dayList = new ArrayList<>();
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

}

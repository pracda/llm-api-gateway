package com.prasiddha.gateway.service;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.ApiKeyRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

/**
 * Admin-provisioned API key lifecycle. Keys are never self-service —
 * an admin creates them for a member of an organization, following a
 * tier preset (Trial/Standard) or explicit limits (Enterprise).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ApiKeyRepository apiKeyRepository;
    private final UserRepository userRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final RealtimeEventPublisher eventPublisher;

    @Value("${app.api-keys.tiers.trial.requests-per-day}")
    private int trialRequestsPerDay;
    @Value("${app.api-keys.tiers.trial.max-tokens-per-request}")
    private int trialMaxTokens;
    @Value("${app.api-keys.tiers.trial.expiry-days}")
    private int trialExpiryDays;
    @Value("${app.api-keys.tiers.trial.daily-budget-usd:0}")
    private double trialDailyBudgetUsd;

    @Value("${app.api-keys.tiers.standard.requests-per-day}")
    private int standardRequestsPerDay;
    @Value("${app.api-keys.tiers.standard.max-tokens-per-request}")
    private int standardMaxTokens;
    @Value("${app.api-keys.tiers.standard.expiry-days}")
    private int standardExpiryDays;
    @Value("${app.api-keys.tiers.standard.daily-budget-usd:0}")
    private double standardDailyBudgetUsd;

    public CreatedKey create(
        String orgId, String username, ApiKey.Tier tier, String name, String adminUsername,
        Integer requestsPerDayOverride, Integer maxTokensPerRequestOverride, Integer expiresInDaysOverride
    ) {
        GatewayUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> new GatewayException("User not found: " + username, HttpStatus.NOT_FOUND));
        if (!orgId.equals(user.getOrganizationId())) {
            throw new GatewayException(
                "User '" + username + "' is not a member of this organization", HttpStatus.BAD_REQUEST);
        }

        int requestsPerDay;
        int maxTokensPerRequest;
        Instant expiresAt;
        Double dailyBudgetUsd;

        switch (tier) {
            case TRIAL -> {
                requestsPerDay = requestsPerDayOverride != null ? requestsPerDayOverride : trialRequestsPerDay;
                maxTokensPerRequest = maxTokensPerRequestOverride != null ? maxTokensPerRequestOverride : trialMaxTokens;
                int days = expiresInDaysOverride != null ? expiresInDaysOverride : trialExpiryDays;
                expiresAt = Instant.now().plus(days, ChronoUnit.DAYS);
                dailyBudgetUsd = trialDailyBudgetUsd > 0 ? trialDailyBudgetUsd : null;
            }
            case STANDARD -> {
                requestsPerDay = requestsPerDayOverride != null ? requestsPerDayOverride : standardRequestsPerDay;
                maxTokensPerRequest = maxTokensPerRequestOverride != null ? maxTokensPerRequestOverride : standardMaxTokens;
                int days = expiresInDaysOverride != null ? expiresInDaysOverride : standardExpiryDays;
                expiresAt = Instant.now().plus(days, ChronoUnit.DAYS);
                dailyBudgetUsd = standardDailyBudgetUsd > 0 ? standardDailyBudgetUsd : null;
            }
            case ENTERPRISE -> {
                if (requestsPerDayOverride == null || maxTokensPerRequestOverride == null) {
                    throw new GatewayException(
                        "Enterprise keys require explicit requestsPerDay and maxTokensPerRequest", HttpStatus.BAD_REQUEST);
                }
                requestsPerDay = requestsPerDayOverride;
                maxTokensPerRequest = maxTokensPerRequestOverride;
                expiresAt = expiresInDaysOverride != null
                    ? Instant.now().plus(expiresInDaysOverride, ChronoUnit.DAYS)
                    : null;
                dailyBudgetUsd = null; // Enterprise keys are unlimited unless set manually after creation
            }
            default -> throw new IllegalStateException("Unknown tier: " + tier);
        }

        String rawKey = generateRawKey();
        ApiKey apiKey = ApiKey.builder()
            .organizationId(orgId)
            .username(username)
            .name(name)
            .keyPrefix(rawKey.substring(0, Math.min(16, rawKey.length())))
            .keyHash(AuditService.hash(rawKey))
            .tier(tier)
            .requestsPerDay(requestsPerDay)
            .maxTokensPerRequest(maxTokensPerRequest)
            .dailyBudgetUsd(dailyBudgetUsd)
            .expiresAt(expiresAt)
            .createdByAdmin(adminUsername)
            .build();

        ApiKey saved = apiKeyRepository.save(apiKey);
        log.info("API key created — org={} user={} tier={} by={}", orgId, username, tier, adminUsername);
        return new CreatedKey(saved, rawKey);
    }

    public List<ApiKey> listForOrg(String orgId) {
        return apiKeyRepository.findByOrganizationIdOrderByCreatedAtDesc(orgId);
    }

    public List<ApiKey> listForUser(String username) {
        return apiKeyRepository.findByUsernameOrderByCreatedAtDesc(username);
    }

    public ApiKey suspend(String id) {
        ApiKey key = get(id);
        key.setStatus(ApiKey.Status.SUSPENDED);
        return apiKeyRepository.save(key);
    }

    public ApiKey resume(String id) {
        ApiKey key = get(id);
        if (key.getStatus() != ApiKey.Status.SUSPENDED) {
            throw new GatewayException("Only suspended keys can be resumed", HttpStatus.BAD_REQUEST);
        }
        key.setStatus(ApiKey.Status.ACTIVE);
        return apiKeyRepository.save(key);
    }

    public ApiKey revoke(String id) {
        ApiKey key = get(id);
        key.setStatus(ApiKey.Status.REVOKED);
        return apiKeyRepository.save(key);
    }

    @Async("auditExecutor")
    public void touchLastUsedAsync(String apiKeyId) {
        apiKeyRepository.findById(apiKeyId).ifPresent(key -> {
            key.setLastUsedAt(Instant.now());
            apiKeyRepository.save(key);
        });
    }

    /** Daily sweep — marks expired keys. No SMTP available, so expiry is surfaced as a dashboard alert, not email. */
    @Scheduled(cron = "0 0 3 * * *")
    public void expireStaleKeys() {
        List<ApiKey> expired = apiKeyRepository.findByStatusAndExpiresAtBefore(ApiKey.Status.ACTIVE, Instant.now());
        for (ApiKey key : expired) {
            key.setStatus(ApiKey.Status.EXPIRED);
            apiKeyRepository.save(key);

            SecurityAlert alert = SecurityAlert.builder()
                .username(key.getUsername())
                .type(SecurityAlert.Type.KEY_EXPIRING)
                .severity(SecurityAlert.Severity.LOW)
                .message("API key '" + key.getName() + "' (" + key.getKeyPrefix() + "...) has expired")
                .build();
            SecurityAlert saved = securityAlertRepository.save(alert);
            eventPublisher.publishAlert(saved);
        }
        if (!expired.isEmpty()) {
            log.info("Expired {} stale API key(s)", expired.size());
        }
    }

    public ApiKey get(String id) {
        return apiKeyRepository.findById(id)
            .orElseThrow(() -> new GatewayException("API key not found: " + id, HttpStatus.NOT_FOUND));
    }

    private String generateRawKey() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return "gw_live_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record CreatedKey(ApiKey apiKey, String rawKey) {}
}

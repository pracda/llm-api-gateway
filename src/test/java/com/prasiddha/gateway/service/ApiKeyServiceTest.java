package com.prasiddha.gateway.service;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.ApiKeyRepository;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import com.prasiddha.gateway.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("ApiKeyService — admin-provisioned key lifecycle")
class ApiKeyServiceTest {

    private ApiKeyRepository apiKeyRepository;
    private UserRepository userRepository;
    private ApiKeyService service;

    @BeforeEach
    void setUp() {
        apiKeyRepository = mock(ApiKeyRepository.class);
        userRepository = mock(UserRepository.class);
        SecurityAlertRepository securityAlertRepository = mock(SecurityAlertRepository.class);
        RealtimeEventPublisher eventPublisher = mock(RealtimeEventPublisher.class);

        service = new ApiKeyService(apiKeyRepository, userRepository, securityAlertRepository, eventPublisher);
        ReflectionTestUtils.setField(service, "trialRequestsPerDay", 100);
        ReflectionTestUtils.setField(service, "trialMaxTokens", 1000);
        ReflectionTestUtils.setField(service, "trialExpiryDays", 7);
        ReflectionTestUtils.setField(service, "standardRequestsPerDay", 2000);
        ReflectionTestUtils.setField(service, "standardMaxTokens", 4000);
        ReflectionTestUtils.setField(service, "standardExpiryDays", 90);

        when(apiKeyRepository.save(any(ApiKey.class))).thenAnswer(inv -> inv.getArgument(0));

        GatewayUser member = GatewayUser.builder().username("alice").organizationId("org-1").build();
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(member));
    }

    @Test
    @DisplayName("generated keys use the gw_live_ prefix, are unique, and hash matches AuditService.hash")
    void createGeneratesUniqueHashedKey() {
        var created1 = service.create("org-1", "alice", ApiKey.Tier.TRIAL, "laptop", "admin", null, null, null);
        var created2 = service.create("org-1", "alice", ApiKey.Tier.TRIAL, "laptop-2", "admin", null, null, null);

        assertThat(created1.rawKey()).startsWith("gw_live_");
        assertThat(created1.rawKey()).isNotEqualTo(created2.rawKey());
        assertThat(created1.apiKey().getKeyHash()).isEqualTo(AuditService.hash(created1.rawKey()));
        assertThat(created1.apiKey().getKeyPrefix()).isEqualTo(created1.rawKey().substring(0, 16));
    }

    @Test
    @DisplayName("Trial tier applies preset limits when no override is given")
    void trialTierUsesPresetDefaults() {
        var created = service.create("org-1", "alice", ApiKey.Tier.TRIAL, "laptop", "admin", null, null, null);

        assertThat(created.apiKey().getRequestsPerDay()).isEqualTo(100);
        assertThat(created.apiKey().getMaxTokensPerRequest()).isEqualTo(1000);
        assertThat(created.apiKey().getExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("Enterprise tier requires explicit requestsPerDay and maxTokensPerRequest")
    void enterpriseTierRequiresExplicitLimits() {
        assertThatThrownBy(() ->
            service.create("org-1", "alice", ApiKey.Tier.ENTERPRISE, "prod", "admin", null, null, null)
        ).isInstanceOf(GatewayException.class);
    }

    @Test
    @DisplayName("Enterprise tier with explicit limits has no expiry unless requested")
    void enterpriseTierNoExpiryByDefault() {
        var created = service.create("org-1", "alice", ApiKey.Tier.ENTERPRISE, "prod", "admin", 50000, 8000, null);

        assertThat(created.apiKey().getRequestsPerDay()).isEqualTo(50000);
        assertThat(created.apiKey().getMaxTokensPerRequest()).isEqualTo(8000);
        assertThat(created.apiKey().getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("Issuing a key for a user outside the organization is rejected")
    void rejectsUserNotInOrganization() {
        GatewayUser outsider = GatewayUser.builder().username("mallory").organizationId("org-2").build();
        when(userRepository.findByUsername("mallory")).thenReturn(Optional.of(outsider));

        assertThatThrownBy(() ->
            service.create("org-1", "mallory", ApiKey.Tier.TRIAL, "key", "admin", null, null, null)
        ).isInstanceOf(GatewayException.class);
    }

    @Test
    @DisplayName("revoke() transitions status to REVOKED")
    void revokeSetsStatus() {
        ApiKey existing = ApiKey.builder().id("key-1").status(ApiKey.Status.ACTIVE).build();
        when(apiKeyRepository.findById("key-1")).thenReturn(Optional.of(existing));

        ApiKey revoked = service.revoke("key-1");

        assertThat(revoked.getStatus()).isEqualTo(ApiKey.Status.REVOKED);
    }

    @Test
    @DisplayName("resume() rejects keys that are not currently suspended")
    void resumeRejectsNonSuspendedKey() {
        ApiKey active = ApiKey.builder().id("key-1").status(ApiKey.Status.ACTIVE).build();
        when(apiKeyRepository.findById("key-1")).thenReturn(Optional.of(active));

        assertThatThrownBy(() -> service.resume("key-1")).isInstanceOf(GatewayException.class);
    }
}

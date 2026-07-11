package com.prasiddha.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.ApiKeyRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.AuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Per-user evidence trail + manual block action, end to end via MockMvc + H2.
 * Follows the same admin-JWT-seeding convention as AdminOrganizationApiKeyTest.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminUserActivityTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired ApiKeyRepository apiKeyRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private String adminJwt() throws Exception {
        String username = "activityadmin";
        if (userRepository.findByUsername(username).isEmpty()) {
            GatewayUser admin = GatewayUser.builder()
                .username(username)
                .passwordHash(passwordEncoder.encode("adminpass123"))
                .role(GatewayUser.Role.ADMIN)
                .build();
            userRepository.save(admin);
        }

        var result = mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", "adminpass123"))))
            .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    @DisplayName("GET /users/{username}/activity returns intent breakdown, keys and lockout state for a registered user")
    void getUserActivity_returnsEvidenceTrail() throws Exception {
        String admin = adminJwt();
        String username = "activityuser";

        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", username, "password", "pass1234"))));

        mockMvc.perform(get("/api/v1/admin/users/" + username + "/activity")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value(username))
            .andExpect(jsonPath("$.enabled").value(true))
            .andExpect(jsonPath("$.locked").value(false))
            .andExpect(jsonPath("$.intentBreakdownLast7d.NORMAL").exists())
            .andExpect(jsonPath("$.intentBreakdownLast7d.SUSPICIOUS").exists())
            .andExpect(jsonPath("$.intentBreakdownLast7d.MALICIOUS").exists())
            .andExpect(jsonPath("$.apiKeys").isArray());
    }

    @Test
    @DisplayName("GET /users/{username}/activity -> 404 for an unknown user")
    void getUserActivity_unknownUser_returns404() throws Exception {
        String admin = adminJwt();

        mockMvc.perform(get("/api/v1/admin/users/does-not-exist/activity")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /users/{username}/block disables the account and revokes all active/suspended keys")
    void blockUser_disablesAccountAndRevokesKeys() throws Exception {
        String admin = adminJwt();
        String username = "blockeduser";

        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", username, "password", "pass1234"))));

        String rawKey = "gw_live_block_test_" + System.nanoTime();
        ApiKey key = ApiKey.builder()
            .organizationId("org-test")
            .username(username)
            .name("test-key")
            .keyPrefix(rawKey.substring(0, Math.min(16, rawKey.length())))
            .keyHash(AuditService.hash(rawKey))
            .tier(ApiKey.Tier.STANDARD)
            .requestsPerDay(1000)
            .maxTokensPerRequest(1000)
            .createdByAdmin("test-harness")
            .build();
        apiKeyRepository.save(key);

        mockMvc.perform(post("/api/v1/admin/users/" + username + "/block")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.apiKeysRevoked").value(1));

        GatewayUser reloaded = userRepository.findByUsername(username).orElseThrow();
        org.assertj.core.api.Assertions.assertThat(reloaded.isEnabled()).isFalse();

        ApiKey reloadedKey = apiKeyRepository.findById(key.getId()).orElseThrow();
        org.assertj.core.api.Assertions.assertThat(reloadedKey.getStatus()).isEqualTo(ApiKey.Status.REVOKED);

        // Blocked user can no longer authenticate at all
        mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", "pass1234"))))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("non-admin cannot reach user activity/block endpoints")
    void nonAdminForbidden() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", "plainuser2", "password", "pass1234"))));

        var result = mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", "plainuser2", "password", "pass1234"))))
            .andReturn();
        String jwt = objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();

        mockMvc.perform(get("/api/v1/admin/users/plainuser2/activity")
                .header("Authorization", "Bearer " + jwt))
            .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/admin/users/plainuser2/block")
                .header("Authorization", "Bearer " + jwt))
            .andExpect(status().isForbidden());
    }
}

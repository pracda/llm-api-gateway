package com.prasiddha.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.UserRepository;
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
 * Admin-provisioned org/API-key lifecycle, end to end via MockMvc + H2.
 * Seeds an admin user directly through the repository rather than relying
 * on DataInitializer's seed timing (not guaranteed deterministic in tests).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminOrganizationApiKeyTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private String adminJwt() throws Exception {
        String username = "testadmin";
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
    @DisplayName("create org -> add member -> issue key -> list (masked) -> suspend -> revoke")
    void fullApiKeyLifecycle() throws Exception {
        String admin = adminJwt();

        // Register the future org member
        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", "orgmember", "password", "pass1234"))));

        // Create organization
        var orgResult = mockMvc.perform(post("/api/v1/admin/organizations")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("name", "Acme-" + System.nanoTime()))))
            .andExpect(status().isOk())
            .andReturn();
        String orgId = objectMapper.readTree(orgResult.getResponse().getContentAsString()).get("id").asText();

        // Add member
        mockMvc.perform(post("/api/v1/admin/organizations/" + orgId + "/members")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", "orgmember"))))
            .andExpect(status().isOk());

        // Issue an API key
        var keyResult = mockMvc.perform(post("/api/v1/admin/organizations/" + orgId + "/api-keys")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                    "username", "orgmember", "tier", "TRIAL", "name", "dev-laptop"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.apiKey").value(org.hamcrest.Matchers.startsWith("gw_live_")))
            .andReturn();

        var keyJson = objectMapper.readTree(keyResult.getResponse().getContentAsString());
        String keyId = keyJson.get("key").get("id").asText();

        // Org detail lists the key, masked (no raw secret field on the nested key object)
        mockMvc.perform(get("/api/v1/admin/organizations/" + orgId)
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.apiKeys[0].keyPrefix").value(org.hamcrest.Matchers.startsWith("gw_live_")))
            .andExpect(jsonPath("$.apiKeys[0].keyHash").doesNotExist());

        // Suspend
        mockMvc.perform(post("/api/v1/admin/api-keys/" + keyId + "/suspend")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("SUSPENDED"));

        // Revoke (permanent)
        mockMvc.perform(delete("/api/v1/admin/api-keys/" + keyId)
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("REVOKED"));
    }

    @Test
    @DisplayName("non-admin cannot reach org/api-key admin endpoints")
    void nonAdminForbidden() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", "plainuser", "password", "pass1234"))));

        var result = mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", "plainuser", "password", "pass1234"))))
            .andReturn();
        String jwt = objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();

        mockMvc.perform(post("/api/v1/admin/organizations")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("name", "ShouldFail"))))
            .andExpect(status().isForbidden());
    }
}

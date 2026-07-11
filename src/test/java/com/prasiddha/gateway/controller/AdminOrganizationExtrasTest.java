package com.prasiddha.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.AuditLogRepository;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Covers three additions: self-service member auto-provisioning (no more
 * requiring a member to /auth/register first), the per-org trend endpoint,
 * and the per-org scoped audit log endpoint.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminOrganizationExtrasTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private String adminJwt() throws Exception {
        String username = "extrasadmin";
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

    private String createOrg(String admin, String name) throws Exception {
        var result = mockMvc.perform(post("/api/v1/admin/organizations")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("name", name))))
            .andExpect(status().isOk())
            .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText();
    }

    private void addMember(String admin, String orgId, String username) throws Exception {
        mockMvc.perform(post("/api/v1/admin/organizations/" + orgId + "/members")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username))))
            .andExpect(status().isOk());
    }

    private AuditLog logFor(String username) {
        return AuditLog.builder()
            .userId(username)
            .promptHash("hash-" + System.nanoTime())
            .provider("OPENAI")
            .model("gpt-4o-mini")
            .outcome(AuditLog.Outcome.SUCCESS)
            .promptTokens(1).completionTokens(1)
            .latencyMs(1).httpStatus(200)
            .jailbreakScore(0)
            .streamed(false)
            .intentClassification(AuditLog.IntentClassification.NORMAL)
            .build();
    }

    @Test
    @DisplayName("adding a member that doesn't exist yet auto-creates the account and returns a working one-time password")
    void addMember_autoCreatesUnregisteredUser() throws Exception {
        String admin = adminJwt();
        String orgId = createOrg(admin, "Extras-" + System.nanoTime());
        String newUsername = "autocreated-" + System.nanoTime();

        var result = mockMvc.perform(post("/api/v1/admin/organizations/" + orgId + "/members")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", newUsername))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accountCreated").value(true))
            .andExpect(jsonPath("$.generatedPassword").exists())
            .andReturn();

        String generatedPassword = objectMapper.readTree(result.getResponse().getContentAsString())
            .get("generatedPassword").asText();

        mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", newUsername, "password", generatedPassword))))
            .andExpect(status().isOk());

        assertThat(userRepository.findByUsername(newUsername)).isPresent();
        assertThat(userRepository.findByUsername(newUsername).get().getOrganizationId()).isEqualTo(orgId);
    }

    @Test
    @DisplayName("adding an already-registered user as member does not create a new account or return a password")
    void addMember_existingUser_noPasswordReturned() throws Exception {
        String admin = adminJwt();
        String orgId = createOrg(admin, "Extras2-" + System.nanoTime());
        String username = "prereg-" + System.nanoTime();

        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", username, "password", "pass1234"))));

        mockMvc.perform(post("/api/v1/admin/organizations/" + orgId + "/members")
                .header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accountCreated").value(false))
            .andExpect(jsonPath("$.generatedPassword").doesNotExist());
    }

    @Test
    @DisplayName("org trend returns 7 day buckets by default, with today's bucket reflecting recorded activity")
    void orgTrend_returnsDayBuckets() throws Exception {
        String admin = adminJwt();
        String orgId = createOrg(admin, "Trend-" + System.nanoTime());
        String username = "trenduser-" + System.nanoTime();
        addMember(admin, orgId, username);
        auditLogRepository.save(logFor(username));

        mockMvc.perform(get("/api/v1/admin/organizations/" + orgId + "/trend")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.days.length()").value(7))
            .andExpect(jsonPath("$.days[6].totalRequests").value(1));
    }

    @Test
    @DisplayName("org report endpoint returns a downloadable PDF covering all members")
    void orgReport_returnsPdf() throws Exception {
        String admin = adminJwt();
        String orgId = createOrg(admin, "Report-" + System.nanoTime());
        String username = "reportuser-" + System.nanoTime();
        addMember(admin, orgId, username);
        auditLogRepository.save(logFor(username));

        var result = mockMvc.perform(get("/api/v1/admin/organizations/" + orgId + "/report?period=weekly")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(header().string("Content-Type", "application/pdf"))
            .andReturn();

        byte[] body = result.getResponse().getContentAsByteArray();
        assertThat(body.length).isGreaterThan(0);
        assertThat(new String(body, 0, 5, java.nio.charset.StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
    }

    @Test
    @DisplayName("org logs endpoint returns only this organization's member activity, not other orgs'")
    void orgLogs_scopedToOrgMembers() throws Exception {
        String admin = adminJwt();
        String orgAId = createOrg(admin, "OrgA-" + System.nanoTime());
        String orgBId = createOrg(admin, "OrgB-" + System.nanoTime());
        String userA = "usera-" + System.nanoTime();
        String userB = "userb-" + System.nanoTime();
        addMember(admin, orgAId, userA);
        addMember(admin, orgBId, userB);

        auditLogRepository.save(logFor(userA));
        auditLogRepository.save(logFor(userB));

        mockMvc.perform(get("/api/v1/admin/organizations/" + orgAId + "/logs")
                .header("Authorization", "Bearer " + admin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(1))
            .andExpect(jsonPath("$.content[0].userId").value(userA));
    }
}

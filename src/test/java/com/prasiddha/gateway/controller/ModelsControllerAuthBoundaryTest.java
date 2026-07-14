package com.prasiddha.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.repository.ApiKeyRepository;
import com.prasiddha.gateway.service.AuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the /api/v1/models auth boundary. Unlike /chat, this endpoint only needs ANY
 * authenticated principal (SecurityConfig's anyRequest().authenticated()) — a JWT alone
 * is sufficient here, since it isn't matched by the /api/v1/chat/** API-key-only rule.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ModelsControllerAuthBoundaryTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired ApiKeyRepository apiKeyRepository;

    private String jwtFor(String username, String password) throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))));

        var result = mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))))
            .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    @DisplayName("no credentials at all -> 401")
    void noCredentials_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/models"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("valid JWT alone -> 200 (unlike /chat, an API key is NOT required here)")
    void jwtOnly_returns200WithModelList() throws Exception {
        String jwt = jwtFor("modelsjwtuser", "pass1234");

        mockMvc.perform(get("/api/v1/models")
                .header("Authorization", "Bearer " + jwt))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.OPENAI.default").isNotEmpty())
            .andExpect(jsonPath("$.OPENAI.allowed").isArray())
            .andExpect(jsonPath("$.ANTHROPIC.default").isNotEmpty())
            .andExpect(jsonPath("$.ANTHROPIC.allowed").isArray());
    }

    @Test
    @DisplayName("valid API key alone -> 200")
    void apiKeyOnly_returns200() throws Exception {
        jwtFor("modelsapikeyuser", "pass1234"); // ensures the owning GatewayUser row exists

        String rawKey = "gw_live_models_test_" + System.nanoTime();
        ApiKey key = ApiKey.builder()
            .organizationId("org-test")
            .username("modelsapikeyuser")
            .name("test-key")
            .keyPrefix(rawKey.substring(0, Math.min(16, rawKey.length())))
            .keyHash(AuditService.hash(rawKey))
            .tier(ApiKey.Tier.STANDARD)
            .requestsPerDay(1000)
            .maxTokensPerRequest(1000)
            .createdByAdmin("test-harness")
            .build();
        apiKeyRepository.save(key);

        mockMvc.perform(get("/api/v1/models")
                .header("X-API-Key", rawKey))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.OPENAI.default").isNotEmpty());
    }
}

package com.prasiddha.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.controller.AuthController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Phase 1 integration tests — verify auth flow end-to-end.
 *
 * Uses an H2 in-memory database so no Docker is needed to run tests.
 * Phase 4 will add Testcontainers for PostgreSQL integration tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @Test
    void registerAndLogin_shouldReturnJwt() throws Exception {
        // Register
        var registerReq = new AuthController.RegisterRequest();
        registerReq.setUsername("testuser");
        registerReq.setPassword("testpass123");

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("testuser"));

        // Login
        var loginReq = new AuthController.LoginRequest();
        loginReq.setUsername("testuser");
        loginReq.setPassword("testpass123");

        mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andExpect(jsonPath("$.type").value("Bearer"));
    }

    @Test
    void login_withWrongPassword_shouldReturn401() throws Exception {
        var loginReq = new AuthController.LoginRequest();
        loginReq.setUsername("nobody");
        loginReq.setPassword("wrongpass");

        mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginReq)))
            .andExpect(status().isUnauthorized());
    }
}

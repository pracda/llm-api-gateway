package com.prasiddha.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prasiddha.gateway.controller.AuthController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Validates the gateway against REAL PostgreSQL and Redis (via Testcontainers), rather than
 * the H2 in-memory substitute the rest of the suite uses (see AuthIntegrationTest). Deliberately
 * runs with real Flyway migrations enabled — so V1/V2/V3 must apply cleanly against Postgres,
 * and Postgres-specific types (e.g. the NUMERIC columns added in V3) are exercised for real,
 * something H2's Hibernate create-drop schema can silently paper over.
 *
 * Requires Docker running locally. Not part of the fast `mvn test` H2 suite by design —
 * run via `mvn verify` (or invoke directly) when Docker is available.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class PostgresIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("llmgateway_test")
        .withUsername("gateway")
        .withPassword("gateway_secret");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
        .withExposedPorts(6379);

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");

        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        // The Testcontainers redis:7-alpine image has no requirepass set — the default
        // profile's "redis_secret" would cause AUTH failures against it, so clear it here.
        registry.add("spring.data.redis.password", () -> "");

        // Non-Postgres/Redis config the app still needs at boot — mirrors application-test.yml
        registry.add("app.jwt.secret", () -> "testcontainers-secret-key-must-be-at-least-32-characters-long");
        registry.add("app.rate-limit.requests-per-minute", () -> 1000);
        registry.add("app.rate-limit.requests-per-day", () -> 100000);
        registry.add("app.rate-limit.global-requests-per-minute", () -> 10000);
        registry.add("app.rate-limit.auth-requests-per-minute", () -> 1000);
        registry.add("app.llm.openai.api-key", () -> "test-openai-key");
        registry.add("app.llm.openai.allowed-models", () -> "gpt-4o-mini,gpt-4o");
        registry.add("app.llm.anthropic.api-key", () -> "test-anthropic-key");
        registry.add("app.llm.anthropic.base-url", () -> "https://api.anthropic.com");
        registry.add("app.llm.anthropic.api-version", () -> "2023-06-01");
        registry.add("app.llm.anthropic.allowed-models", () -> "claude-haiku-4-5-20251001");
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @Test
    void registerAndLogin_shouldSucceedAgainstRealPostgresAndRedis() throws Exception {
        var registerReq = new AuthController.RegisterRequest();
        registerReq.setUsername("pguser");
        registerReq.setPassword("testpass123");

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("pguser"));

        var loginReq = new AuthController.LoginRequest();
        loginReq.setUsername("pguser");
        loginReq.setPassword("testpass123");

        mockMvc.perform(post("/api/v1/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andExpect(jsonPath("$.type").value("Bearer"));
    }
}

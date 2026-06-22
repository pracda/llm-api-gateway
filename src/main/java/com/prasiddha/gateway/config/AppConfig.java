package com.prasiddha.gateway.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.concurrent.Executor;

@Configuration
public class AppConfig {

    /** Shared WebClient for outbound LLM provider HTTP calls */
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
            .codecs(c -> c.defaultCodecs().maxInMemorySize(10 * 1024 * 1024))
            .build();
    }

    /** Dedicated thread pool for @Async audit logging */
    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
        exec.setCorePoolSize(4);
        exec.setMaxPoolSize(16);
        exec.setQueueCapacity(200);
        exec.setThreadNamePrefix("audit-");
        exec.initialize();
        return exec;
    }

    /** Swagger UI with JWT auth button */
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Secure LLM API Gateway")
                .description("""
                    Proxies OpenAI and Anthropic APIs with:
                    - JWT authentication
                    - Per-user rate limiting
                    - Prompt injection detection (OWASP LLM #01)
                    - Output sanitisation (OWASP LLM #05)
                    - Full audit logging
                    """)
                .version("1.0.0"))
            .schemaRequirement("bearerAuth",
                new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Get a token from POST /api/v1/auth/token")
            );
    }
}

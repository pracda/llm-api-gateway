package com.prasiddha.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Secure LLM API Gateway
 *
 * Security pipeline (every request):
 *   Client → JWT Auth → Rate Limit → Input Scan → LLM → Output Scan → Client
 *
 * OWASP LLM Top 10 coverage:
 *   #01 Prompt Injection     → InputScanFilter
 *   #05 Improper Output      → OutputScanService
 *   #06 Sensitive Info Disc. → AuditService (hashes prompts, never stores raw)
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}

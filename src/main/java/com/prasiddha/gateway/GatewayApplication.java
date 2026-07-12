package com.prasiddha.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.TimeZone;

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

    // Runs on class-load (both `main()` at runtime and Spring's test bootstrapper for
    // @SpringBootTest, since this class is the configuration source either way) — pins the
    // JVM default timezone to UTC. Without this, java.sql.Timestamp round-trips through
    // whatever timezone the host happens to be in, which can silently shift day-bucketed
    // queries (audit log trend/report, "requests today") by several hours near local midnight.
    static {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    }

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}

package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Persists audit entries on a dedicated thread pool (@Async).
 * The HTTP response is never blocked waiting for the DB write.
 *
 * Raw prompts are hashed (SHA-256) before storage — OWASP LLM #06.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository repository;
    private final RealtimeEventPublisher eventPublisher;
    private final GatewayMetrics metrics;

    @Async("auditExecutor")
    public void log(AuditLog entry) {
        // F5: emit Prometheus metrics from the single audit chokepoint — every outcome, one place.
        try {
            metrics.recordAudit(entry);
        } catch (Exception e) {
            log.debug("Metrics emission failed (ignoring): {}", e.getMessage());
        }
        try {
            repository.save(entry);
            eventPublisher.publishAudit(entry);
        } catch (Exception e) {
            // Audit failures MUST NOT affect the client response
            log.error("Audit log write failed: {}", e.getMessage());
        }
    }

    /** SHA-256 hash of raw text — safe to store for deduplication */
    public static String hash(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return "hash-unavailable";
        }
    }
}

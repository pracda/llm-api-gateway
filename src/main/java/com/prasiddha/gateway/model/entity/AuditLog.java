package com.prasiddha.gateway.model.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * Immutable record of every gateway request.
 * Raw prompts are NEVER stored — only a SHA-256 hash (OWASP LLM #06).
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_user",      columnList = "userId"),
    @Index(name = "idx_audit_created",   columnList = "createdAt"),
    @Index(name = "idx_audit_outcome",   columnList = "outcome")
})
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class AuditLog {

    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String userId;

    /** SHA-256(prompt) — allows deduplication without storing content */
    @Column(nullable = false, length = 64)
    private String promptHash;

    @Column(nullable = false, length = 20)
    private String provider;

    @Column(length = 100)
    private String model;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private Outcome outcome;

    /** Populated when outcome is a BLOCKED_* variant */
    @Column(length = 200)
    private String blockReason;

    private int promptTokens;
    private int completionTokens;
    private long latencyMs;
    private int httpStatus;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() { createdAt = Instant.now(); }

    public enum Outcome {
        SUCCESS,
        BLOCKED_INPUT_INJECTION,   // OWASP LLM #01
        BLOCKED_OUTPUT_UNSAFE,     // OWASP LLM #05
        BLOCKED_RATE_LIMIT,
        BLOCKED_AUTH,
        ERROR
    }
}

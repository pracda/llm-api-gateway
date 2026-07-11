package com.prasiddha.gateway.model.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * Admin-provisioned gateway credential. The raw secret is shown to the
 * admin exactly once at creation time and is never persisted — only a
 * SHA-256 hash (see AuditService.hash) is stored, mirroring how prompts
 * are never stored in AuditLog.
 */
@Entity
@Table(name = "api_keys", indexes = {
    @Index(name = "idx_apikey_hash", columnList = "keyHash", unique = true),
    @Index(name = "idx_apikey_org",  columnList = "organizationId"),
    @Index(name = "idx_apikey_user", columnList = "username")
})
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class ApiKey {

    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String organizationId;

    /** Owning user's username — matches how AuditLog.userId is keyed throughout the app. */
    @Column(nullable = false)
    private String username;

    @Column(nullable = false, length = 100)
    private String name;

    /** First ~12 chars of the raw key — safe to display for identification. */
    @Column(nullable = false, length = 20)
    private String keyPrefix;

    /** SHA-256 hex of the full raw key. */
    @Column(nullable = false, unique = true, length = 64)
    private String keyHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Tier tier;

    @Column(nullable = false)
    private int requestsPerDay;

    @Column(nullable = false)
    private int maxTokensPerRequest;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    /** Null = no expiry (typical for Enterprise tier). */
    private Instant expiresAt;

    private Instant lastUsedAt;

    @Column(nullable = false)
    private String createdByAdmin;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        if (status == null) status = Status.ACTIVE;
    }

    public enum Tier { TRIAL, STANDARD, ENTERPRISE }

    public enum Status { ACTIVE, SUSPENDED, REVOKED, EXPIRED }
}

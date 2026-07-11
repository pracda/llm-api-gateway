package com.prasiddha.gateway.model.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "security_alerts", indexes = {
    @Index(name = "idx_alert_created",      columnList = "createdAt"),
    @Index(name = "idx_alert_acknowledged", columnList = "acknowledged"),
    @Index(name = "idx_alert_severity",     columnList = "severity")
})
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class SecurityAlert {

    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Nullable — some alert types (e.g. COORDINATED_ATTACK) aren't tied to one account. */
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private Type type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Severity severity;

    @Column(nullable = false, length = 500)
    private String message;

    @Column(nullable = false)
    private boolean autoLockApplied;

    @Column(nullable = false)
    private boolean acknowledged;

    private String acknowledgedBy;

    private Instant acknowledgedAt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    public enum Type {
        REPEATED_INJECTION,
        REPEATED_OUTPUT_BLOCK,
        RATE_LIMIT_ABUSE,
        LOGIN_BRUTE_FORCE,
        MULTI_IP_ACCESS,
        COORDINATED_ATTACK,
        PROMPT_LEAK_DETECTED,
        KEY_EXPIRING,
        ELEVATED_JAILBREAK_SCORE,
        COMPETITOR_MENTION
    }

    public enum Severity { LOW, MEDIUM, HIGH }
}

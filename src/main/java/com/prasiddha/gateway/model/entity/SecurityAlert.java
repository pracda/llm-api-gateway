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
        COMPETITOR_MENTION,
        USER_MANUALLY_BLOCKED,
        MODEL_EXTRACTION_SUSPECTED;

        /** Short, layman-readable label for the dashboard — the enum name itself is for logs/APIs only. */
        public String friendlyLabel() {
            return switch (this) {
                case REPEATED_INJECTION          -> "Repeated prompt injection attempts";
                case REPEATED_OUTPUT_BLOCK        -> "Repeated unsafe AI responses blocked";
                case RATE_LIMIT_ABUSE             -> "Excessive request volume (rate limit abuse)";
                case LOGIN_BRUTE_FORCE            -> "Repeated failed logins (possible brute force)";
                case MULTI_IP_ACCESS              -> "Same account used from many different locations";
                case COORDINATED_ATTACK           -> "Coordinated attack pattern across multiple accounts";
                case PROMPT_LEAK_DETECTED         -> "System prompt leak detected";
                case KEY_EXPIRING                 -> "API key expired";
                case ELEVATED_JAILBREAK_SCORE     -> "Elevated jailbreak risk detected";
                case COMPETITOR_MENTION           -> "Competitor mentioned in AI response";
                case USER_MANUALLY_BLOCKED        -> "Account manually blocked by admin";
                case MODEL_EXTRACTION_SUSPECTED   -> "Suspicious model extraction attempt detected";
            };
        }
    }

    public enum Severity { LOW, MEDIUM, HIGH }
}

package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.SecurityAlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Rule-based, Redis-backed threat detection with automatic temporary
 * lockout — same fail-open posture as RateLimitService: any Redis error
 * is logged and swallowed so infra trouble never blocks legitimate traffic.
 *
 * Lockout uses an atomic SETNX (opsForValue().setIfAbsent), not a plain
 * count comparison. A count comparison would only fire exactly once
 * (count == threshold) and could never re-trigger if an admin manually
 * clears the lockout early while the offender keeps offending within the
 * same counting window (count would already be past the threshold and
 * never equal it again). SETNX naturally re-arms as soon as the lockout
 * key is gone, and guarantees exactly one SecurityAlert per lockout
 * transition (repeated calls while a lockout is active just fail to
 * acquire, so no alert spam).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatDetectionService {

    private final StringRedisTemplate redis;
    private final SecurityAlertRepository securityAlertRepository;
    private final RealtimeEventPublisher eventPublisher;
    private final AlertNotificationService alertNotificationService;

    @Value("${app.security.threat-detection.window-seconds}")
    private long windowSeconds;
    @Value("${app.security.threat-detection.lockout-seconds}")
    private long lockoutSeconds;
    @Value("${app.security.threat-detection.injection-attempts-threshold}")
    private long injectionThreshold;
    @Value("${app.security.threat-detection.output-block-threshold}")
    private long outputBlockThreshold;
    @Value("${app.security.threat-detection.rate-limit-abuse-threshold}")
    private long rateLimitAbuseThreshold;
    @Value("${app.security.threat-detection.failed-login-threshold}")
    private long failedLoginThreshold;
    @Value("${app.security.threat-detection.distinct-ip-threshold}")
    private long distinctIpThreshold;
    @Value("${app.security.threat-detection.coordinated-attack-user-threshold}")
    private long coordinatedAttackUserThreshold;
    @Value("${app.security.threat-detection.extraction-suspicion-window-seconds}")
    private long extractionSuspicionWindowSeconds;
    @Value("${app.security.threat-detection.extraction-suspicion-threshold}")
    private long extractionSuspicionThreshold;

    // ── Public API ───────────────────────────────────────────────────────

    /** Records one occurrence of a per-account abuse signal; may trigger a lockout. */
    public void recordEvent(String username, SecurityAlert.Type type) {
        try {
            long threshold = thresholdFor(type);
            String counterKey = "threat:" + type.name() + ":" + username;
            Long count = redis.opsForValue().increment(counterKey);
            if (count != null && count == 1) {
                redis.expire(counterKey, windowSeconds, TimeUnit.SECONDS);
            }
            if (count != null && count >= threshold) {
                maybeLockAndAlert(username, type, describeCount(type, count));
            }
        } catch (Exception e) {
            log.error("Threat detection recordEvent failed, ignoring: {}", e.getMessage());
        }
    }

    /** Tracks distinct source IPs per account within the window; may trigger MULTI_IP_ACCESS. */
    public void recordIp(String username, String ip) {
        if (ip == null || ip.isBlank()) return;
        try {
            String key = "threat:ip-set:" + username;
            redis.opsForSet().add(key, ip);
            redis.expire(key, windowSeconds, TimeUnit.SECONDS);
            Long distinctCount = redis.opsForSet().size(key);
            if (distinctCount != null && distinctCount >= distinctIpThreshold) {
                maybeLockAndAlert(username, SecurityAlert.Type.MULTI_IP_ACCESS,
                    distinctCount + " distinct IPs in the last " + windowSeconds + "s");
            }
        } catch (Exception e) {
            log.error("Threat detection recordIp failed, ignoring: {}", e.getMessage());
        }
    }

    /**
     * Cross-user correlation: the same coarse attack signature (e.g. an
     * injection-pattern category, never the raw prompt) tried by several
     * distinct accounts in a short window suggests a coordinated attack.
     * Alert-only — deliberately never auto-locks, since it's ambiguous
     * which of the involved accounts is actually malicious.
     */
    public void recordAttackSignature(String signature, String username) {
        if (username == null) return;
        try {
            String key = "threat:signature:" + signature;
            redis.opsForSet().add(key, username);
            redis.expire(key, windowSeconds, TimeUnit.SECONDS);
            Long distinctUsers = redis.opsForSet().size(key);
            if (distinctUsers != null && distinctUsers >= coordinatedAttackUserThreshold) {
                String lockKey = "threat:signature-alerted:" + signature;
                boolean firstAlert = Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(lockKey, "1", windowSeconds, TimeUnit.SECONDS));
                if (firstAlert) {
                    persistAndPublish(null, SecurityAlert.Type.COORDINATED_ATTACK, SecurityAlert.Severity.HIGH,
                        distinctUsers + " distinct accounts tried the same attack pattern ('" + signature + "') within " + windowSeconds + "s",
                        false);
                }
            }
        } catch (Exception e) {
            log.error("Threat detection recordAttackSignature failed, ignoring: {}", e.getMessage());
        }
    }

    public boolean isLocked(String username) {
        try {
            return Boolean.TRUE.equals(redis.hasKey(lockoutKey(username)));
        } catch (Exception e) {
            log.error("Threat detection isLocked check failed, failing open: {}", e.getMessage());
            return false;
        }
    }

    public long lockoutRemainingSeconds(String username) {
        try {
            Long ttl = redis.getExpire(lockoutKey(username), TimeUnit.SECONDS);
            return (ttl != null && ttl > 0) ? ttl : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /** Manual admin override — clears the lockout early. */
    public void unlock(String username) {
        redis.delete(lockoutKey(username));
    }

    /**
     * Raises a SecurityAlert immediately, bypassing the occurrence-count
     * threshold — for signals that are significant on the very first
     * occurrence (e.g. a confirmed system-prompt leak).
     */
    public void raiseImmediateAlert(String username, SecurityAlert.Type type, String message) {
        try {
            persistAndPublish(username, type, severityFor(type), message, false);
        } catch (Exception e) {
            log.error("Failed to raise immediate alert: {}", e.getMessage());
        }
    }

    /**
     * Short-window burst counter (request SHAPE, not total count — distinct
     * from RateLimitService). Observability signal only: feeds the risk
     * score / dashboard, does not add another auto-lockout trigger.
     */
    public long recordBurst(String username) {
        try {
            String key = "threat:burst:" + username;
            Long count = redis.opsForValue().increment(key);
            if (count != null && count == 1) {
                redis.expire(key, 3, TimeUnit.SECONDS);
            }
            return count != null ? count : 0;
        } catch (Exception e) {
            log.error("Burst tracking failed, ignoring: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Sustained-success-volume signal — the practical, content-free proxy for
     * "model extraction" abuse (OWASP LLM10). We don't own the underlying model
     * (it's the upstream provider's), so classic weight-extraction doesn't apply
     * here; the real risk is a script hammering the API with a high volume of
     * SUCCESSFUL calls to distill a copycat model. Rate-limit-abuse only fires on
     * REJECTED requests, so a caller sitting just under the limit but sustaining
     * it far longer than any normal chat session would never trip that signal —
     * this is a distinct counter for exactly that shape. Alert-only, like
     * COORDINATED_ATTACK: high volume alone isn't proof of theft, an admin
     * should judge it, so it never auto-locks.
     */
    public void recordSuccess(String username) {
        try {
            String key = "threat:success-volume:" + username;
            Long count = redis.opsForValue().increment(key);
            if (count != null && count == 1) {
                redis.expire(key, extractionSuspicionWindowSeconds, TimeUnit.SECONDS);
            }
            if (count != null && count >= extractionSuspicionThreshold) {
                String dedupeKey = "threat:success-volume-alerted:" + username;
                boolean firstAlert = Boolean.TRUE.equals(
                    redis.opsForValue().setIfAbsent(dedupeKey, "1", extractionSuspicionWindowSeconds, TimeUnit.SECONDS));
                if (firstAlert) {
                    persistAndPublish(username, SecurityAlert.Type.MODEL_EXTRACTION_SUSPECTED, SecurityAlert.Severity.HIGH,
                        username + " made " + count + " successful requests in " + extractionSuspicionWindowSeconds
                            + "s — volume consistent with automated model extraction/distillation",
                        false);
                }
            }
        } catch (Exception e) {
            log.error("Extraction-suspicion volume tracking failed, ignoring: {}", e.getMessage());
        }
    }

    // ── IP blocklist (dashboard "Block IP" action) ──────────────────────

    private static final String BLOCKED_IPS_KEY = "threat:blocked-ips";

    public boolean isIpBlocked(String ip) {
        try {
            return Boolean.TRUE.equals(redis.opsForSet().isMember(BLOCKED_IPS_KEY, ip));
        } catch (Exception e) {
            log.error("IP blocklist check failed, failing open: {}", e.getMessage());
            return false;
        }
    }

    public void blockIp(String ip) {
        redis.opsForSet().add(BLOCKED_IPS_KEY, ip);
    }

    public void unblockIp(String ip) {
        redis.opsForSet().remove(BLOCKED_IPS_KEY, ip);
    }

    public Set<String> listBlockedIps() {
        Set<String> members = redis.opsForSet().members(BLOCKED_IPS_KEY);
        return members != null ? members : Set.of();
    }

    // ── Private helpers ──────────────────────────────────────────────────

    private void maybeLockAndAlert(String username, SecurityAlert.Type type, String detail) {
        boolean acquired = Boolean.TRUE.equals(
            redis.opsForValue().setIfAbsent(lockoutKey(username), type.name(), lockoutSeconds, TimeUnit.SECONDS));
        if (acquired) {
            String message = username + " triggered " + type.name() + " (" + detail + ") — account locked for "
                + lockoutSeconds + "s";
            persistAndPublish(username, type, severityFor(type), message, true);
        }
    }

    private void persistAndPublish(
        String username, SecurityAlert.Type type, SecurityAlert.Severity severity, String message, boolean autoLocked
    ) {
        SecurityAlert alert = SecurityAlert.builder()
            .username(username)
            .type(type)
            .severity(severity)
            .message(message)
            .autoLockApplied(autoLocked)
            .build();
        SecurityAlert saved = securityAlertRepository.save(alert);
        eventPublisher.publishAlert(saved);
        alertNotificationService.notifyIfHighSeverity(saved);
        log.warn("SECURITY ALERT [{}] {} — {}", severity, type, message);
    }

    private long thresholdFor(SecurityAlert.Type type) {
        return switch (type) {
            case REPEATED_INJECTION -> injectionThreshold;
            case REPEATED_OUTPUT_BLOCK -> outputBlockThreshold;
            case RATE_LIMIT_ABUSE -> rateLimitAbuseThreshold;
            case LOGIN_BRUTE_FORCE -> failedLoginThreshold;
            default -> Long.MAX_VALUE;
        };
    }

    private SecurityAlert.Severity severityFor(SecurityAlert.Type type) {
        return switch (type) {
            case REPEATED_INJECTION, LOGIN_BRUTE_FORCE, PROMPT_LEAK_DETECTED, COORDINATED_ATTACK, USER_MANUALLY_BLOCKED, MODEL_EXTRACTION_SUSPECTED -> SecurityAlert.Severity.HIGH;
            case REPEATED_OUTPUT_BLOCK, RATE_LIMIT_ABUSE, MULTI_IP_ACCESS, ELEVATED_JAILBREAK_SCORE -> SecurityAlert.Severity.MEDIUM;
            case KEY_EXPIRING, COMPETITOR_MENTION -> SecurityAlert.Severity.LOW;
        };
    }

    private String describeCount(SecurityAlert.Type type, long count) {
        return count + " occurrences of " + type.name() + " in the last " + windowSeconds + "s";
    }

    private String lockoutKey(String username) {
        return "threat:lockout:" + username;
    }
}

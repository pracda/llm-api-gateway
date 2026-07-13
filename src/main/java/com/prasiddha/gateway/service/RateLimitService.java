package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Per-user rate limiting backed by Redis.
 *
 * Uses Redis atomic increment (INCR + EXPIRE) — a battle-tested
 * pattern that works across multiple app instances.
 *
 * Algorithm:
 *   1. INCR rate:minute:{userId}  — atomic counter
 *   2. If count == 1, set EXPIRE 60s (first request opens window)
 *   3. If count > limit, reject 429
 *   4. Repeat for daily bucket
 *
 * Redis keys:
 *   rate:minute:{userId}  — expires after 60 seconds
 *   rate:day:{userId}     — expires after 24 hours
 */
@Slf4j
@Service
public class RateLimitService {

    @Value("${app.rate-limit.requests-per-minute}")
    private int requestsPerMinute;

    @Value("${app.rate-limit.requests-per-day}")
    private int requestsPerDay;

    @Value("${app.rate-limit.global-requests-per-minute}")
    private int globalRequestsPerMinute;

    @Value("${app.rate-limit.auth-requests-per-minute}")
    private int authRequestsPerMinute;

    private final StringRedisTemplate redis;

    public RateLimitService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /**
     * Per-IP rate limit for pre-authentication endpoints (register/login), where no
     * userId exists yet. keyPrefix distinguishes independent buckets per endpoint
     * (e.g. "register" vs "token") since registration spam and login brute-force
     * are different threat shapes.
     */
    public RateLimitResult checkIpLimit(String ip, String keyPrefix) {
        try {
            return checkWindow(
                "rate:auth:" + keyPrefix + ":" + ip,
                authRequestsPerMinute,
                60L,
                TimeUnit.SECONDS,
                "auth-ip"
            );
        } catch (Exception e) {
            log.error("Auth IP rate limit check failed, allowing request: {}", e.getMessage());
            return RateLimitResult.allowed(-1);
        }
    }

    public RateLimitResult checkLimit(String userId) {
        try {
            // Check global (cross-user) limit first
            RateLimitResult globalResult = checkWindow(
                "rate:global:minute",
                globalRequestsPerMinute,
                60L,
                TimeUnit.SECONDS,
                "global"
            );
            if (!globalResult.isAllowed()) return globalResult;

            // Check per-minute limit next
            RateLimitResult minuteResult = checkWindow(
                "rate:minute:" + userId,
                requestsPerMinute,
                60L,
                TimeUnit.SECONDS,
                "per-minute"
            );
            if (!minuteResult.isAllowed()) return minuteResult;

            // Then check per-day limit
            return checkWindow(
                "rate:day:" + userId,
                requestsPerDay,
                86400L,
                TimeUnit.SECONDS,
                "per-day"
            );

        } catch (Exception e) {
            // Redis down — fail open (allow request) to avoid blocking all traffic
            log.error("Rate limit check failed, allowing request: {}", e.getMessage());
            return RateLimitResult.allowed(-1);
        }
    }

    /**
     * Current accumulated $ spend for an API key in the running 24h window — read-only,
     * used for the PRE-call budget check (the exact cost of the current call isn't known
     * until after the LLM responds, so only prior spend can be checked before dispatch).
     */
    public double getCurrentSpend(String apiKeyId) {
        try {
            String value = redis.opsForValue().get("spend:day:" + apiKeyId);
            return value != null ? Double.parseDouble(value) : 0.0;
        } catch (Exception e) {
            log.error("Spend lookup failed, treating as zero: {}", e.getMessage());
            return 0.0;
        }
    }

    /**
     * Records actual spend for a completed call — POST-call only. Naturally starts blocking
     * the NEXT request once the running total crosses the budget cap (same count-then-check
     * trade-off as checkWindow above).
     */
    public void recordSpend(String apiKeyId, double costUsd) {
        if (costUsd <= 0) return;
        try {
            String key = "spend:day:" + apiKeyId;
            Double total = redis.opsForValue().increment(key, costUsd); // Redis INCRBYFLOAT
            if (total != null && total.doubleValue() == costUsd) {
                redis.expire(key, 86400L, TimeUnit.SECONDS); // first write this window
            }
        } catch (Exception e) {
            log.error("Spend recording failed for apiKeyId={}: {}", apiKeyId, e.getMessage());
        }
    }

    private RateLimitResult checkWindow(
        String key, int limit, long ttl, TimeUnit unit, String limitType
    ) {
        Long count = redis.opsForValue().increment(key);
        if (count == null) return RateLimitResult.allowed(-1);

        // Set expiry on first request in the window
        if (count == 1) {
            redis.expire(key, ttl, unit);
        }

        if (count > limit) {
            Long ttlRemaining = redis.getExpire(key, TimeUnit.SECONDS);
            long retryAfter   = (ttlRemaining != null && ttlRemaining > 0) ? ttlRemaining : ttl;
            log.warn("Rate limit EXCEEDED — key={} count={}/{} retryAfter={}s",
                key, count, limit, retryAfter);
            return RateLimitResult.exceeded(retryAfter, limitType);
        }

        long remaining = Math.max(0, limit - count);
        log.debug("Rate limit OK — key={} count={}/{} remaining={}", key, count, limit, remaining);
        return RateLimitResult.allowed(remaining);
    }

    public record RateLimitResult(
        boolean allowed,
        long remainingTokens,
        long retryAfterSeconds,
        String limitType
    ) {
        static RateLimitResult allowed(long remaining) {
            return new RateLimitResult(true, remaining, 0, null);
        }
        static RateLimitResult exceeded(long retryAfterSeconds, String limitType) {
            return new RateLimitResult(false, 0, retryAfterSeconds, limitType);
        }
        public boolean isAllowed() { return allowed; }
    }
}

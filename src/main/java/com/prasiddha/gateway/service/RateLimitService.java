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

    private final StringRedisTemplate redis;

    public RateLimitService(StringRedisTemplate redis) {
        this.redis = redis;
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

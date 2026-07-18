package com.prasiddha.gateway.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
public class GatewayException extends RuntimeException {

    /**
     * How the fallback ladder (F6) should treat a provider failure:
     * <ul>
     *   <li>{@code RETRYABLE_TRANSIENT} — 5xx/timeout; retry the same provider, then advance.</li>
     *   <li>{@code USAGE_BLOCKED} — provider 429/402/quota, or an own budget cap; skip retry,
     *       advance straight to the next rung (preferring free).</li>
     *   <li>{@code NON_RETRYABLE} — 400/401/bad model; throw immediately, no laddering.</li>
     * </ul>
     */
    public enum ErrorClass { RETRYABLE_TRANSIENT, USAGE_BLOCKED, NON_RETRYABLE }

    private final HttpStatus status;
    private final Long retryAfterSeconds;
    private final String limitType;
    /** Fallback-ladder classification of this failure. */
    private final ErrorClass errorClass;

    public GatewayException(String message, HttpStatus status) {
        this(message, status, null, null);
    }

    public GatewayException(String message, HttpStatus status, Long retryAfterSeconds, String limitType) {
        this(message, status, retryAfterSeconds, limitType, false);
    }

    public GatewayException(String message, HttpStatus status, Long retryAfterSeconds, String limitType, boolean retryable) {
        this(message, status, retryAfterSeconds, limitType,
            retryable ? ErrorClass.RETRYABLE_TRANSIENT : ErrorClass.NON_RETRYABLE);
    }

    public GatewayException(String message, HttpStatus status, Long retryAfterSeconds, String limitType, ErrorClass errorClass) {
        super(message);
        this.status = status;
        this.retryAfterSeconds = retryAfterSeconds;
        this.limitType = limitType;
        this.errorClass = errorClass;
    }

    /** True when the failure is transient (a provider 5xx/timeout) and safe to retry the same provider. */
    public boolean isRetryable() {
        return errorClass == ErrorClass.RETRYABLE_TRANSIENT;
    }

    /** True when a paid provider is out of quota/rate-limited (429/402) — advance to a free rung. */
    public boolean isUsageBlocked() {
        return errorClass == ErrorClass.USAGE_BLOCKED;
    }

    /** Used by /chat/stream, whose SseEmitter-declared return type rules out the manual-ResponseEntity-with-headers approach /chat uses. */
    public static GatewayException rateLimited(long retryAfterSeconds, String limitType) {
        return new GatewayException("Rate limit exceeded: " + limitType, HttpStatus.TOO_MANY_REQUESTS, retryAfterSeconds, limitType);
    }

    public static GatewayException locked(long retryAfterSeconds) {
        return new GatewayException("Account temporarily locked due to suspicious activity",
            HttpStatus.LOCKED, retryAfterSeconds, null);
    }

    public static GatewayException ipBlocked() {
        return new GatewayException("IP address blocked by admin", HttpStatus.FORBIDDEN);
    }

    public static GatewayException injectionDetected() {
        return new GatewayException("Request blocked: prompt injection detected.", HttpStatus.BAD_REQUEST);
    }

    public static GatewayException piiDetected() {
        return new GatewayException("Request blocked: PII detected in prompt.", HttpStatus.BAD_REQUEST);
    }

    public static GatewayException unsafeOutput() {
        return new GatewayException("Response blocked: unsafe content detected in LLM output.", HttpStatus.BAD_REQUEST);
    }

    public static GatewayException providerError(String provider) {
        return providerError(provider, false);
    }

    public static GatewayException providerError(String provider, boolean retryable) {
        return new GatewayException(
            "LLM provider error from " + provider + ". Please try again.", HttpStatus.BAD_GATEWAY, null, null, retryable);
    }

    /** Provider is rate-limited or out of quota (429/402) — usage-blocked, so the ladder advances (F6). */
    public static GatewayException providerUsageBlocked(String provider) {
        return new GatewayException(
            "LLM provider " + provider + " is rate-limited or out of quota.",
            HttpStatus.BAD_GATEWAY, null, null, ErrorClass.USAGE_BLOCKED);
    }

    /**
     * Classifies a provider HTTP error into the fallback-ladder error class (F6):
     * 5xx/timeout → transient (retry same), 429/402 → usage-blocked (advance rung),
     * everything else (400/401/…) → non-retryable (throw).
     */
    public static GatewayException fromProviderStatus(String provider, HttpStatusCode status) {
        if (status.is5xxServerError()) {
            return providerError(provider, true);
        }
        if (status.value() == 429 || status.value() == 402) {
            return providerUsageBlocked(provider);
        }
        return providerError(provider, false);
    }

    public static GatewayException invalidModel(String model, String provider) {
        return new GatewayException(
            "Model '" + model + "' is not permitted for provider " + provider, HttpStatus.BAD_REQUEST);
    }

    public static GatewayException budgetExceeded(double spentUsd, double budgetUsd) {
        return new GatewayException(
            "Daily budget exceeded: $" + String.format("%.4f", spentUsd) + " / $" + String.format("%.2f", budgetUsd),
            HttpStatus.PAYMENT_REQUIRED);
    }
}

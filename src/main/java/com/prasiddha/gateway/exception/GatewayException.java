package com.prasiddha.gateway.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class GatewayException extends RuntimeException {
    private final HttpStatus status;
    private final Long retryAfterSeconds;
    private final String limitType;

    public GatewayException(String message, HttpStatus status) {
        this(message, status, null, null);
    }

    public GatewayException(String message, HttpStatus status, Long retryAfterSeconds, String limitType) {
        super(message);
        this.status = status;
        this.retryAfterSeconds = retryAfterSeconds;
        this.limitType = limitType;
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
        return new GatewayException("LLM provider error from " + provider + ". Please try again.", HttpStatus.BAD_GATEWAY);
    }
}

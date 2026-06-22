package com.prasiddha.gateway.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class GatewayException extends RuntimeException {
    private final HttpStatus status;

    public GatewayException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public static GatewayException rateLimited() {
        return new GatewayException("Rate limit exceeded. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
    }

    public static GatewayException injectionDetected() {
        return new GatewayException("Request blocked: prompt injection detected.", HttpStatus.BAD_REQUEST);
    }

    public static GatewayException unsafeOutput() {
        return new GatewayException("Response blocked: unsafe content detected in LLM output.", HttpStatus.BAD_REQUEST);
    }

    public static GatewayException providerError(String provider) {
        return new GatewayException("LLM provider error from " + provider + ". Please try again.", HttpStatus.BAD_GATEWAY);
    }
}

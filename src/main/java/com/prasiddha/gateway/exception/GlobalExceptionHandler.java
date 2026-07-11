package com.prasiddha.gateway.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Centralises error handling so we never leak stack traces or
 * internal details to clients (OWASP LLM #06).
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = ex.getBindingResult().getFieldErrors().stream()
            .collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage));
        return ResponseEntity.badRequest().body(errorBody("Validation failed", errors));
    }

    @ExceptionHandler(GatewayException.class)
    public ResponseEntity<Map<String, Object>> handleGateway(GatewayException ex) {
        log.warn("Gateway exception: {}", ex.getMessage());
        Map<String, Object> body = errorBody(ex.getMessage(), null);
        if (ex.getRetryAfterSeconds() != null) {
            body.put("retryAfterSeconds", ex.getRetryAfterSeconds());
        }
        if (ex.getLimitType() != null) {
            body.put("limitType", ex.getLimitType());
        }
        return ResponseEntity.status(ex.getStatus()).body(body);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuth(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(errorBody("Authentication required", null));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccess(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(errorBody("Insufficient permissions", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(errorBody("An unexpected error occurred", null));
    }

    private Map<String, Object> errorBody(String message, Object details) {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("timestamp", Instant.now().toString());
        body.put("error", message);
        if (details != null) body.put("details", details);
        return body;
    }
}

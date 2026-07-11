package com.prasiddha.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Rejections thrown by AuthorizationFilter (e.g. hasAuthority/hasRole URL
 * matchers) are caught by ExceptionTranslationFilter INSIDE the security
 * chain — they never reach GlobalExceptionHandler's @RestControllerAdvice,
 * which only sees exceptions from inside DispatcherServlet. Without this,
 * an anonymous request to a protected path falls back to Spring Boot's
 * default /error page instead of this app's JSON error shape.
 */
@Component
@RequiredArgsConstructor
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
        HttpServletRequest request, HttpServletResponse response, AuthenticationException authException
    ) throws java.io.IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("error", "Authentication required");

        objectMapper.writeValue(response.getWriter(), body);
    }
}

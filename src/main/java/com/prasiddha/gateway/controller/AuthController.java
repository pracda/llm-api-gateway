package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.security.JwtUtil;
import com.prasiddha.gateway.service.RateLimitService;
import com.prasiddha.gateway.service.ThreatDetectionService;
import com.prasiddha.gateway.util.ClientIpResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ThreatDetectionService threatDetectionService;
    private final RateLimitService rateLimitService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest httpRequest) {
        String ip = ClientIpResolver.resolve(httpRequest);
        RateLimitService.RateLimitResult rateResult = rateLimitService.checkIpLimit(ip, "register");
        if (!rateResult.isAllowed()) {
            log.warn("Registration rate limit exceeded for ip={}", ip);
            throw GatewayException.rateLimited(rateResult.retryAfterSeconds(), rateResult.limitType());
        }

        if (userRepository.existsByUsername(req.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already taken"));
        }
        GatewayUser user = GatewayUser.builder()
            .username(req.getUsername())
            .passwordHash(passwordEncoder.encode(req.getPassword()))
            .role(GatewayUser.Role.USER)
            .build();
        userRepository.save(user);
        log.info("Registered user: {}", req.getUsername());
        return ResponseEntity.ok(Map.of("message", "Registered successfully", "username", user.getUsername()));
    }

    @PostMapping("/token")
    @Operation(summary = "Login — returns a JWT token")
    public ResponseEntity<?> token(@Valid @RequestBody LoginRequest req, HttpServletRequest httpRequest) {
        String ip = ClientIpResolver.resolve(httpRequest);
        RateLimitService.RateLimitResult rateResult = rateLimitService.checkIpLimit(ip, "token");
        if (!rateResult.isAllowed()) {
            log.warn("Login rate limit exceeded for ip={}", ip);
            throw GatewayException.rateLimited(rateResult.retryAfterSeconds(), rateResult.limitType());
        }

        if (threatDetectionService.isLocked(req.getUsername())) {
            long retryAfter = threatDetectionService.lockoutRemainingSeconds(req.getUsername());
            log.warn("Login rejected — account temporarily locked: {}", req.getUsername());
            return ResponseEntity.status(HttpStatus.LOCKED)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter))
                .body(Map.of("error", "Account temporarily locked due to suspicious activity"));
        }

        try {
            authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
        } catch (BadCredentialsException e) {
            threatDetectionService.recordEvent(req.getUsername(), SecurityAlert.Type.LOGIN_BRUTE_FORCE);
            throw e;
        }

        GatewayUser user = userRepository.findByUsername(req.getUsername()).orElseThrow();
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name());
        log.info("JWT issued for: {}", user.getUsername());
        return ResponseEntity.ok(Map.of("token", token, "type", "Bearer", "expiresIn", "86400s"));
    }

    @Data public static class RegisterRequest {
        @NotBlank private String username;
        @NotBlank private String password;
    }

    @Data public static class LoginRequest {
        @NotBlank private String username;
        @NotBlank private String password;
    }
}

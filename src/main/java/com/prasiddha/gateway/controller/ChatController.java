package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import com.prasiddha.gateway.service.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Primary gateway endpoint.
 *
 * Full security pipeline per request:
 *   1. JWT auth (Spring Security filter — before this controller)
 *   2. Rate limiting  (RateLimitService)
 *   3. Input scan     (InputScanService)   ← OWASP LLM #01
 *   4. LLM call       (stub in Phase 1 — real providers in Phase 2)
 *   5. Output scan    (OutputScanService)  ← OWASP LLM #05
 *   6. Audit log      (AuditService — async, never blocks response)
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Tag(name = "Chat Gateway")
public class ChatController {

    private final InputScanService inputScan;
    private final OutputScanService outputScan;
    private final AuditService auditService;
    // private final LlmProxyService llmProxy;  // Phase 2

    @PostMapping("/chat")
    @Operation(
        summary = "Send a prompt through the secure gateway",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<ChatResponse> chat(
        @Valid @RequestBody ChatRequest request,
        @AuthenticationPrincipal String username
    ) {
        long start = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        log.info("[{}] user='{}' provider={}", requestId, username, request.getProvider());

        // ── Step 1: Input scan ─────────────────────────────────────────
        InputScanService.ScanResult inputResult =
            inputScan.scan(request.getUserMessage(), request.getSystemPrompt());

        if (inputResult.isDetected() && inputResult.shouldBlock()) {
            auditService.log(buildAuditLog(username, request, AuditLog.Outcome.BLOCKED_INPUT_INJECTION,
                inputResult.reason(), 0, 0, elapsed(start), 400));
            throw GatewayException.injectionDetected();
        }

        // ── Step 2: LLM call (Phase 1 stub) ───────────────────────────
        // TODO Phase 2: replace with real llmProxy.chat(request)
        String rawLlmOutput = "Hello from the Secure LLM Gateway! " +
            "Provider: " + request.getProvider() + ". " +
            "Your message was received and scanned for injection. " +
            "Real LLM integration coming in Phase 2.";

        int promptTokens = 0, completionTokens = 0;  // Phase 2: real counts

        // ── Step 3: Output scan ────────────────────────────────────────
        OutputScanService.ScanResult outputResult = outputScan.scan(rawLlmOutput);

        if (outputResult.isBlocked()) {
            auditService.log(buildAuditLog(username, request, AuditLog.Outcome.BLOCKED_OUTPUT_UNSAFE,
                outputResult.reason(), promptTokens, completionTokens, elapsed(start), 400));
            throw GatewayException.unsafeOutput();
        }

        String finalContent = outputResult.content();

        // ── Step 4: Audit log (async) ──────────────────────────────────
        auditService.log(buildAuditLog(username, request, AuditLog.Outcome.SUCCESS,
            null, promptTokens, completionTokens, elapsed(start), 200));

        ChatResponse response = ChatResponse.builder()
            .requestId(requestId)
            .content(finalContent)
            .provider(request.getProvider().name().toLowerCase())
            .model(request.getModel() != null ? request.getModel() : "stub-phase1")
            .usage(ChatResponse.TokenUsage.builder()
                .promptTokens(promptTokens)
                .completionTokens(completionTokens)
                .totalTokens(promptTokens + completionTokens)
                .build())
            .latencyMs(elapsed(start))
            .outputSanitised(outputResult.isSanitised())
            .build();

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    @Operation(summary = "Authenticated health check", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> health(@AuthenticationPrincipal String username) {
        return ResponseEntity.ok(Map.of("status", "UP", "user", username));
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private AuditLog buildAuditLog(
        String userId, ChatRequest req, AuditLog.Outcome outcome,
        String blockReason, int promptTokens, int completionTokens,
        long latencyMs, int httpStatus
    ) {
        return AuditLog.builder()
            .userId(userId)
            .promptHash(AuditService.hash(req.getUserMessage()))
            .provider(req.getProvider().name())
            .model(req.getModel())
            .outcome(outcome)
            .blockReason(blockReason)
            .promptTokens(promptTokens)
            .completionTokens(completionTokens)
            .latencyMs(latencyMs)
            .httpStatus(httpStatus)
            .build();
    }

    private long elapsed(long start) { return System.currentTimeMillis() - start; }
}

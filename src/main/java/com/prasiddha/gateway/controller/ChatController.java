package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import com.prasiddha.gateway.proxy.LlmProxyService;
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

/**
 * Primary gateway endpoint.
 *
 * Security pipeline per request:
 *   1. JWT auth     (Spring Security filter)
 *   2. Input scan   (InputScanService)   ← OWASP LLM #01
 *   3. LLM call     (LlmProxyService → OpenAI or Anthropic)
 *   4. Output scan  (OutputScanService)  ← OWASP LLM #05
 *   5. Audit log    (AuditService — async)
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
    private final LlmProxyService llmProxy;

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
        log.info("Chat — user='{}' provider={}", username, request.getProvider());

        // ── 1. Input scan ──────────────────────────────────────────────
        InputScanService.ScanResult inputResult =
            inputScan.scan(request.getUserMessage(), request.getSystemPrompt());

        if (inputResult.isDetected() && inputResult.shouldBlock()) {
            auditService.log(buildAudit(username, request,
                AuditLog.Outcome.BLOCKED_INPUT_INJECTION,
                inputResult.reason(), 0, 0, elapsed(start), 400));
            throw GatewayException.injectionDetected();
        }

        // ── 2. Real LLM call ───────────────────────────────────────────
        ChatResponse llmResponse = llmProxy.chat(request);

        // ── 3. Output scan ─────────────────────────────────────────────
        OutputScanService.ScanResult outputResult =
            outputScan.scan(llmResponse.getContent());

        if (outputResult.isBlocked()) {
            auditService.log(buildAudit(username, request,
                AuditLog.Outcome.BLOCKED_OUTPUT_UNSAFE,
                outputResult.reason(),
                llmResponse.getUsage().getPromptTokens(),
                llmResponse.getUsage().getCompletionTokens(),
                elapsed(start), 400));
            throw GatewayException.unsafeOutput();
        }

        // ── 4. Audit log (async) ───────────────────────────────────────
        auditService.log(buildAudit(username, request,
            AuditLog.Outcome.SUCCESS, null,
            llmResponse.getUsage().getPromptTokens(),
            llmResponse.getUsage().getCompletionTokens(),
            elapsed(start), 200));

        // If output was sanitised, update content and flag it
        ChatResponse finalResponse = outputResult.isSanitised()
            ? ChatResponse.builder()
                .requestId(llmResponse.getRequestId())
                .content(outputResult.content())
                .provider(llmResponse.getProvider())
                .model(llmResponse.getModel())
                .usage(llmResponse.getUsage())
                .latencyMs(elapsed(start))
                .outputSanitised(true)
                .build()
            : llmResponse;

        return ResponseEntity.ok(finalResponse);
    }

    @GetMapping("/health")
    @Operation(summary = "Authenticated health check",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> health(@AuthenticationPrincipal String username) {
        return ResponseEntity.ok(Map.of("status", "UP", "user", username));
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private AuditLog buildAudit(
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

    private long elapsed(long start) {
        return System.currentTimeMillis() - start;
    }
}

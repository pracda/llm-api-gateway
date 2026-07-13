package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.AuditLog;
import com.prasiddha.gateway.model.entity.SecurityAlert;
import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ChatResponse;
import com.prasiddha.gateway.proxy.LlmProxyService;
import com.prasiddha.gateway.service.*;
import com.prasiddha.gateway.util.ClientIpResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Primary gateway endpoint.
 *
 * Full security pipeline per request (shared by both /chat and /chat/stream):
 *   0. IP blocklist + account lockout (ThreatDetectionService)
 *   1. Rate limit    (RateLimitService → Redis)
 *   2. Input scan    (InputScanService)   ← OWASP LLM #01 + jailbreak score + input PII
 *   3. LLM call      (LlmProxyService → OpenAI or Anthropic, token-budget capped)
 *   4. Output scan   (OutputScanService)  ← OWASP LLM #05 + canary leak + competitor mention
 *   5. Audit log     (AuditService — async)
 *
 * /chat/stream trades away pre-delivery output blocking/redaction: tokens are
 * forwarded to the caller as they arrive, so step 4 can only run AFTER the full
 * response has already been sent — it can still alert, auto-revoke, and count
 * toward the same threshold-based lockouts, just not stop delivery.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Tag(name = "Chat Gateway")
public class ChatController {

    private final InputScanService       inputScan;
    private final OutputScanService      outputScan;
    private final AuditService           auditService;
    private final LlmProxyService        llmProxy;
    private final RateLimitService       rateLimitService;
    private final ThreatDetectionService threatDetectionService;
    private final ApiKeyService          apiKeyService;
    private final IntentClassificationService intentClassificationService;
    private final CostCalculationService costCalculationService;

    @Value("${app.llm.openai.default-model}")
    private String openAiDefaultModel;
    @Value("${app.llm.anthropic.default-model}")
    private String anthropicDefaultModel;

    @PostMapping("/chat")
    @Operation(
        summary = "Send a prompt through the secure gateway",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<ChatResponse> chat(
        @Valid @RequestBody ChatRequest request,
        @AuthenticationPrincipal String username,
        @RequestAttribute(name = "apiKeyId", required = false) String apiKeyId,
        HttpServletRequest httpRequest
    ) {
        long start = System.currentTimeMillis();
        String ip  = ClientIpResolver.resolve(httpRequest);
        log.info("Chat — user='{}' provider={} ip={}", username, request.getProvider(), ip);

        // ── 0. IP blocklist + account lockout ───────────────────────────
        if (threatDetectionService.isIpBlocked(ip)) {
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_AUTH, "IP address blocked by admin",
                0, 0, elapsed(start), 403, false, true, false));
            return ResponseEntity.status(403).build();
        }

        if (threatDetectionService.isLocked(username)) {
            long retryAfter = threatDetectionService.lockoutRemainingSeconds(username);
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_AUTH, "Account temporarily locked due to suspicious activity",
                0, 0, elapsed(start), 423, false, false, true));
            return ResponseEntity.status(HttpStatus.LOCKED)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter))
                .build();
        }

        threatDetectionService.recordIp(username, ip);
        threatDetectionService.recordBurst(username); // observability signal only, no lockout

        // ── 1. Rate limit check ────────────────────────────────────────
        RateLimitService.RateLimitResult rateResult = rateLimitService.checkLimit(username);
        if (!rateResult.isAllowed()) {
            threatDetectionService.recordEvent(username, SecurityAlert.Type.RATE_LIMIT_ABUSE);
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_RATE_LIMIT,
                "Rate limit exceeded: " + rateResult.limitType(),
                0, 0, elapsed(start), 429, false, false, threatDetectionService.isLocked(username)));

            return ResponseEntity.status(429)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(rateResult.retryAfterSeconds()))
                .header("X-RateLimit-LimitType", rateResult.limitType())
                .build();
        }

        // ── 1b. Budget check (uses PRIOR accumulated spend — this call's exact cost isn't
        // known until the LLM responds, so this can only catch "already over budget") ──────
        ApiKey apiKey = apiKeyService.get(apiKeyId);
        Double dailyBudgetUsd = apiKey.getDailyBudgetUsd();
        if (dailyBudgetUsd != null && dailyBudgetUsd > 0) {
            double currentSpend = rateLimitService.getCurrentSpend(apiKeyId);
            if (currentSpend > dailyBudgetUsd) {
                auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                    AuditLog.Outcome.BLOCKED_BUDGET_EXCEEDED,
                    "Daily budget exceeded: $" + currentSpend + " / $" + dailyBudgetUsd,
                    0, 0, elapsed(start), 402, false));
                throw GatewayException.budgetExceeded(currentSpend, dailyBudgetUsd);
            }
        }

        // ── 2. Input scan (injection detection + jailbreak score) ──────
        InputScanService.ScanResult inputResult =
            inputScan.scan(request.getUserMessage(), request.getSystemPrompt());

        if (inputResult.isDetected() && inputResult.shouldBlock()) {
            threatDetectionService.recordEvent(username, SecurityAlert.Type.REPEATED_INJECTION);
            threatDetectionService.recordAttackSignature(inputResult.reason(), username);
            auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
                AuditLog.Outcome.BLOCKED_INPUT_INJECTION,
                inputResult.reason(), 0, 0, elapsed(start), 400, false));
            throw GatewayException.injectionDetected();
        }

        if (inputResult.jailbreakScore() >= 50 && !inputResult.isDetected()) {
            // Elevated but under the block threshold — flag for review, don't block or lock.
            threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.ELEVATED_JAILBREAK_SCORE,
                "Elevated jailbreak risk score (" + inputResult.jailbreakScore() + "/100) from " + username);
        }

        // ── 2b. PII detection on the prompt itself, before it ever reaches the LLM ──
        InputScanService.PiiScanResult piiResult = inputScan.scanForPii(request.getUserMessage());
        if (piiResult.isBlocked()) {
            auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
                AuditLog.Outcome.BLOCKED_INPUT_INJECTION, piiResult.reason(), 0, 0, elapsed(start), 400, false));
            throw GatewayException.piiDetected();
        }
        if (piiResult.content() != null) {
            request.setUserMessage(piiResult.content());
        }

        // ── 3. Real LLM call (token budget capped by the caller's API key tier) ──
        int maxTokens = apiKey.getMaxTokensPerRequest();
        ChatResponse llmResponse = llmProxy.chat(request, maxTokens);

        // Cost is incurred by the provider call regardless of what the output scan decides below,
        // so it's computed and recorded here, once, and threaded into whichever audit log follows.
        double costUsd = costCalculationService.computeCostUsd(
            llmResponse.getProvider(), llmResponse.getModel(),
            llmResponse.getUsage().getPromptTokens(), llmResponse.getUsage().getCompletionTokens());
        rateLimitService.recordSpend(apiKeyId, costUsd);

        // ── 4. Output scan ─────────────────────────────────────────────
        OutputScanService.ScanResult outputResult =
            outputScan.scan(llmResponse.getContent());

        if (outputResult.isBlocked()) {
            threatDetectionService.recordEvent(username, SecurityAlert.Type.REPEATED_OUTPUT_BLOCK);
            if (outputResult.promptLeakDetected() && apiKeyId != null) {
                apiKeyService.revoke(apiKeyId);
                threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.PROMPT_LEAK_DETECTED,
                    "System prompt leak detected for user '" + username + "' — API key " + apiKeyId + " auto-revoked");
            }
            auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
                AuditLog.Outcome.BLOCKED_OUTPUT_UNSAFE,
                outputResult.reason(),
                llmResponse.getUsage().getPromptTokens(),
                llmResponse.getUsage().getCompletionTokens(),
                elapsed(start), 400, false).toBuilder().costUsd(costUsd).build());
            throw GatewayException.unsafeOutput();
        }

        if (outputResult.competitorMentioned()) {
            threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.COMPETITOR_MENTION,
                "Competitor mention in response to '" + username + "'");
        }

        // ── 5. Audit log (async — never blocks response) ───────────────
        threatDetectionService.recordSuccess(username);
        auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
            AuditLog.Outcome.SUCCESS, null,
            llmResponse.getUsage().getPromptTokens(),
            llmResponse.getUsage().getCompletionTokens(),
            elapsed(start), 200, false, false, threatDetectionService.isLocked(username))
            .toBuilder().costUsd(costUsd).build());

        ChatResponse finalResponse = outputResult.isSanitised()
            ? llmResponse.toBuilder()
                .content(outputResult.content())
                .latencyMs(elapsed(start))
                .outputSanitised(true)
                .build()
            : llmResponse;

        // Add rate limit headers to every successful response
        return ResponseEntity.ok()
            .header("X-RateLimit-Remaining", String.valueOf(rateResult.remainingTokens()))
            .body(finalResponse);
    }

    @PostMapping(value = "/chat/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(
        summary = "Send a prompt through the secure gateway with token-by-token streaming",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public SseEmitter chatStream(
        @Valid @RequestBody ChatRequest request,
        @AuthenticationPrincipal String username,
        @RequestAttribute(name = "apiKeyId", required = false) String apiKeyId,
        HttpServletRequest httpRequest
    ) {
        long start = System.currentTimeMillis();
        String ip  = ClientIpResolver.resolve(httpRequest);
        log.info("ChatStream — user='{}' provider={} ip={}", username, request.getProvider(), ip);

        // ── 0. IP blocklist + account lockout ───────────────────────────
        // Thrown (not manually built ResponseEntity, since this method must be declared to
        // return SseEmitter) — Spring's exception resolution runs before return-value handling,
        // so this behaves identically to /chat as long as it happens before the emitter exists.
        if (threatDetectionService.isIpBlocked(ip)) {
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_AUTH, "IP address blocked by admin",
                0, 0, elapsed(start), 403, true, true, false));
            throw GatewayException.ipBlocked();
        }

        if (threatDetectionService.isLocked(username)) {
            long retryAfter = threatDetectionService.lockoutRemainingSeconds(username);
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_AUTH, "Account temporarily locked due to suspicious activity",
                0, 0, elapsed(start), 423, true, false, true));
            throw GatewayException.locked(retryAfter);
        }

        threatDetectionService.recordIp(username, ip);
        threatDetectionService.recordBurst(username);

        // ── 1. Rate limit check ────────────────────────────────────────
        RateLimitService.RateLimitResult rateResult = rateLimitService.checkLimit(username);
        if (!rateResult.isAllowed()) {
            threatDetectionService.recordEvent(username, SecurityAlert.Type.RATE_LIMIT_ABUSE);
            auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                AuditLog.Outcome.BLOCKED_RATE_LIMIT,
                "Rate limit exceeded: " + rateResult.limitType(),
                0, 0, elapsed(start), 429, true, false, threatDetectionService.isLocked(username)));
            throw GatewayException.rateLimited(rateResult.retryAfterSeconds(), rateResult.limitType());
        }

        // ── 1b. Budget check (uses PRIOR accumulated spend — see /chat for why) ──
        ApiKey apiKey = apiKeyService.get(apiKeyId);
        Double dailyBudgetUsd = apiKey.getDailyBudgetUsd();
        if (dailyBudgetUsd != null && dailyBudgetUsd > 0) {
            double currentSpend = rateLimitService.getCurrentSpend(apiKeyId);
            if (currentSpend > dailyBudgetUsd) {
                auditService.log(buildAudit(username, request, apiKeyId, ip, 0,
                    AuditLog.Outcome.BLOCKED_BUDGET_EXCEEDED,
                    "Daily budget exceeded: $" + currentSpend + " / $" + dailyBudgetUsd,
                    0, 0, elapsed(start), 402, true));
                throw GatewayException.budgetExceeded(currentSpend, dailyBudgetUsd);
            }
        }

        // ── 2. Input scan (injection detection + jailbreak score) ──────
        InputScanService.ScanResult inputResult =
            inputScan.scan(request.getUserMessage(), request.getSystemPrompt());

        if (inputResult.isDetected() && inputResult.shouldBlock()) {
            threatDetectionService.recordEvent(username, SecurityAlert.Type.REPEATED_INJECTION);
            threatDetectionService.recordAttackSignature(inputResult.reason(), username);
            auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
                AuditLog.Outcome.BLOCKED_INPUT_INJECTION,
                inputResult.reason(), 0, 0, elapsed(start), 400, true));
            throw GatewayException.injectionDetected();
        }

        if (inputResult.jailbreakScore() >= 50 && !inputResult.isDetected()) {
            threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.ELEVATED_JAILBREAK_SCORE,
                "Elevated jailbreak risk score (" + inputResult.jailbreakScore() + "/100) from " + username);
        }

        // ── 2b. PII detection on the prompt itself, before it ever reaches the LLM ──
        InputScanService.PiiScanResult piiResult = inputScan.scanForPii(request.getUserMessage());
        if (piiResult.isBlocked()) {
            auditService.log(buildAudit(username, request, apiKeyId, ip, inputResult.jailbreakScore(),
                AuditLog.Outcome.BLOCKED_INPUT_INJECTION, piiResult.reason(), 0, 0, elapsed(start), 400, true));
            throw GatewayException.piiDetected();
        }
        if (piiResult.content() != null) {
            request.setUserMessage(piiResult.content());
        }

        // ── 3. Stream from the provider (token budget capped by the caller's API key tier) ──
        int maxTokens = apiKey.getMaxTokensPerRequest();
        int jailbreakScore = inputResult.jailbreakScore();

        SseEmitter emitter = new SseEmitter(0L);
        StringBuilder accumulated = new StringBuilder();
        AtomicReference<ChatResponse.TokenUsage> finalUsage = new AtomicReference<>();

        // Wire format is intentionally plain data:-only frames terminated by a literal
        // "data: [DONE]" (no named SSE events) — matches the OpenAI-style raw streaming
        // convention external clients commonly already parse. Token usage/outcome are still
        // fully captured server-side in the audit log regardless of what's sent over the wire.
        llmProxy.streamChat(request, maxTokens).subscribe(
            chunk -> {
                try {
                    if (chunk.textDelta() != null) {
                        emitter.send(SseEmitter.event().data(chunk.textDelta()));
                        accumulated.append(chunk.textDelta());
                    }
                    if (chunk.done()) {
                        finalUsage.set(chunk.finalUsage());
                    }
                } catch (IOException | IllegalStateException e) {
                    log.debug("Stream send failed (client likely disconnected): {}", e.getMessage());
                }
            },
            error -> {
                log.error("Chat stream error for user='{}': {}", username, error.getMessage());
                try {
                    // In-band error marker — a fixed, unambiguous prefix so it can't be mistaken
                    // for real model output, followed by the same [DONE] terminator as success.
                    emitter.send(SseEmitter.event().data("[GATEWAY_ERROR: " + error.getMessage() + "]"));
                    emitter.send(SseEmitter.event().data("[DONE]"));
                } catch (IOException | IllegalStateException ignored) {
                    // response already committed/closed — nothing more we can tell the client
                }
                auditService.log(buildAudit(username, request, apiKeyId, ip, jailbreakScore,
                    AuditLog.Outcome.ERROR, error.getMessage(), 0, 0, elapsed(start), 502, true,
                    false, threatDetectionService.isLocked(username)));
                emitter.complete();
            },
            () -> {
                // Content is already fully delivered — output scanning here can only alert/
                // auto-revoke/count-toward-lockout, never block or redact what was already sent.
                String content = accumulated.toString();
                OutputScanService.ScanResult outputResult = outputScan.scan(content);
                ChatResponse.TokenUsage usage = finalUsage.get();
                int promptTokens     = usage != null ? usage.getPromptTokens() : 0;
                int completionTokens = usage != null ? usage.getCompletionTokens() : 0;

                // Streaming never returns a ChatResponse with the resolved model, so the
                // provider default is looked up here the same way OpenAiProvider/AnthropicProvider
                // resolve it internally.
                String model = request.getModel() != null ? request.getModel()
                    : request.getProvider() == ChatRequest.LlmProvider.OPENAI ? openAiDefaultModel : anthropicDefaultModel;
                double costUsd = costCalculationService.computeCostUsd(
                    request.getProvider().name(), model, promptTokens, completionTokens);
                rateLimitService.recordSpend(apiKeyId, costUsd);

                if (outputResult.isBlocked()) {
                    threatDetectionService.recordEvent(username, SecurityAlert.Type.REPEATED_OUTPUT_BLOCK);
                    if (outputResult.promptLeakDetected() && apiKeyId != null) {
                        apiKeyService.revoke(apiKeyId);
                        threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.PROMPT_LEAK_DETECTED,
                            "System prompt leak detected for user '" + username + "' — API key " + apiKeyId +
                                " auto-revoked (streamed response, could not be blocked pre-delivery)");
                    }
                }
                if (outputResult.competitorMentioned()) {
                    threatDetectionService.raiseImmediateAlert(username, SecurityAlert.Type.COMPETITOR_MENTION,
                        "Competitor mention in streamed response to '" + username + "'");
                }

                threatDetectionService.recordSuccess(username);
                auditService.log(buildAudit(username, request, apiKeyId, ip, jailbreakScore,
                    AuditLog.Outcome.SUCCESS, null, promptTokens, completionTokens, elapsed(start), 200, true,
                    false, threatDetectionService.isLocked(username), outputResult.isBlocked())
                    .toBuilder().costUsd(costUsd).build());

                try {
                    emitter.send(SseEmitter.event().data("[DONE]"));
                } catch (IOException | IllegalStateException ignored) {
                }
                emitter.complete();
            }
        );

        return emitter;
    }

    @GetMapping("/health")
    @Operation(summary = "Authenticated health check",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<?> health(@AuthenticationPrincipal String username) {
        return ResponseEntity.ok(Map.of("status", "UP", "user", username));
    }

    private AuditLog buildAudit(
        String userId, ChatRequest req, String apiKeyId, String ipAddress, int jailbreakScore,
        AuditLog.Outcome outcome, String blockReason, int promptTokens, int completionTokens,
        long latencyMs, int httpStatus, boolean streamed
    ) {
        return buildAudit(userId, req, apiKeyId, ipAddress, jailbreakScore, outcome, blockReason,
            promptTokens, completionTokens, latencyMs, httpStatus, streamed, false, false);
    }

    private AuditLog buildAudit(
        String userId, ChatRequest req, String apiKeyId, String ipAddress, int jailbreakScore,
        AuditLog.Outcome outcome, String blockReason, int promptTokens, int completionTokens,
        long latencyMs, int httpStatus, boolean streamed, boolean ipBlocked, boolean accountLocked
    ) {
        return buildAudit(userId, req, apiKeyId, ipAddress, jailbreakScore, outcome, blockReason,
            promptTokens, completionTokens, latencyMs, httpStatus, streamed, ipBlocked, accountLocked,
            outcome == AuditLog.Outcome.BLOCKED_OUTPUT_UNSAFE);
    }

    /**
     * outputBlocked is an explicit override (not derived from outcome) because streamed
     * responses can be flagged as unsafe AFTER full delivery — the outcome is still logged
     * as SUCCESS (content already reached the client), but the intent classification must
     * still reflect that the output scan actually flagged it.
     */
    private AuditLog buildAudit(
        String userId, ChatRequest req, String apiKeyId, String ipAddress, int jailbreakScore,
        AuditLog.Outcome outcome, String blockReason, int promptTokens, int completionTokens,
        long latencyMs, int httpStatus, boolean streamed, boolean ipBlocked, boolean accountLocked,
        boolean outputBlocked
    ) {
        IntentClassificationService.Result intent = intentClassificationService.classify(
            new IntentClassificationService.Signals(
                ipBlocked,
                accountLocked,
                outcome == AuditLog.Outcome.BLOCKED_INPUT_INJECTION,
                outputBlocked,
                jailbreakScore
            )
        );

        return AuditLog.builder()
            .userId(userId)
            .apiKeyId(apiKeyId)
            .ipAddress(ipAddress)
            .jailbreakScore(jailbreakScore)
            .promptHash(AuditService.hash(req.getUserMessage()))
            .provider(req.getProvider().name())
            .model(req.getModel())
            .outcome(outcome)
            .blockReason(blockReason)
            .promptTokens(promptTokens)
            .completionTokens(completionTokens)
            .latencyMs(latencyMs)
            .httpStatus(httpStatus)
            .streamed(streamed)
            .intentClassification(intent.classification())
            .intentReason(intent.reason())
            .build();
    }

    private long elapsed(long start) {
        return System.currentTimeMillis() - start;
    }
}

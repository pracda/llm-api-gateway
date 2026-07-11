package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Scans incoming prompts for prompt injection attacks.
 * Covers OWASP LLM Top 10 #01 — Prompt Injection.
 *
 * Detection strategies:
 *   1. Direct injection patterns (instruction override phrases)
 *   2. Role-play / persona hijacking
 *   3. Encoded payloads (Base64, Unicode escapes)
 *   4. System prompt extraction attempts
 */
@Slf4j
@Service
public class InputScanService {

    @Value("${app.security.input.injection-detection-enabled}")
    private boolean enabled;

    @Value("${app.security.input.block-on-detection}")
    private boolean blockOnDetection;

    /** REDACT or BLOCK when PII is found in the user's prompt, before it's ever sent to the LLM. */
    @Value("${app.security.input.pii-action}")
    private String piiAction;

    // ── Injection patterns ────────────────────────────────────────────────

    private static final List<Pattern> INJECTION_PATTERNS = List.of(

        // Instruction override
        Pattern.compile("ignore (all |previous |prior |above |the )*(instructions?|prompts?|directives?|rules?|constraints?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard (all |previous |prior |above |the )*(instructions?|prompts?|directives?|rules?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("forget (all |everything|your|previous|prior)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("override (your |the |all )?(instructions?|system|rules?|constraints?)", Pattern.CASE_INSENSITIVE),

        // Persona / role hijacking
        Pattern.compile("you are now", Pattern.CASE_INSENSITIVE),
        Pattern.compile("act as (if |though )?(you are|a|an|the)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pretend (you are|to be|that you)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("your (new |true |real )?(role|identity|persona|purpose|goal) is", Pattern.CASE_INSENSITIVE),
        Pattern.compile("switch (to|into) (a |an |the )?(different |new )?mode", Pattern.CASE_INSENSITIVE),

        // Jailbreak signals
        Pattern.compile("jailbreak", Pattern.CASE_INSENSITIVE),
        Pattern.compile("DAN mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("developer mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("unrestricted mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("without (any |your )?(restrictions?|limitations?|filters?|guidelines?)", Pattern.CASE_INSENSITIVE),

        // System prompt extraction
        Pattern.compile("(reveal|show|print|output|repeat|tell me|what (is|are)) (your |the )?(system|original|initial|hidden) (prompt|instructions?|context)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("what (were|are) you (told|instructed|programmed|trained|prompted)", Pattern.CASE_INSENSITIVE),

        // Delimiter injection (trying to inject new system prompt sections)
        Pattern.compile("```\\s*(system|assistant|human|user)\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<(system|assistant|human|user)>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\[INST\\]|\\[/INST\\]|<<SYS>>|<</SYS>>"),

        // Token smuggling signals
        Pattern.compile("\\\\u[0-9a-fA-F]{4}.*\\\\u[0-9a-fA-F]{4}"),   // Unicode escapes
        Pattern.compile("\\\\x[0-9a-fA-F]{2}.*\\\\x[0-9a-fA-F]{2}")    // Hex escapes
    );

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Scans the prompt for injection signals AND computes a 0-100 heuristic
     * jailbreak risk score, logged on every request (even passing ones) so
     * trend lines are visible on the dashboard. NOTE: the score is derived
     * from the same regex/heuristic signals as the block/allow decision —
     * it adds observability, not new paraphrase-evasion resistance (that
     * would need a semantic LLM-based pass, deliberately out of scope here).
     */
    public ScanResult scan(String userMessage, String systemPrompt) {
        if (!enabled) {
            return ScanResult.clean(0);
        }

        int score = 0;
        String reason = null;

        // 1. Base64-encoded injection payloads
        String decodedHit = findBase64InjectionPayload(userMessage);
        if (decodedHit != null) {
            reason = "Base64-encoded injection payload detected";
            score += 40;
            log.warn("INPUT SCAN — base64 injection, decoded preview='{}'", preview(decodedHit));
        }

        // 2. Direct pattern matches — tally all hits for the score, keep the first for the reason
        int patternMatches = 0;
        for (Pattern pattern : INJECTION_PATTERNS) {
            if (pattern.matcher(userMessage).find()) {
                patternMatches++;
                if (reason == null) {
                    reason = "Injection pattern detected: " + pattern.pattern();
                }
                log.warn("INPUT SCAN — pattern='{}' preview='{}'", pattern.pattern(), preview(userMessage));
            }
        }
        score += Math.min(patternMatches, 3) * 25;

        // 3. System prompt override heuristic
        if (systemPrompt != null && looksLikeSystemPromptOverride(userMessage, systemPrompt)) {
            if (reason == null) {
                reason = "Possible system prompt override attempt";
            }
            score += 20;
            log.warn("INPUT SCAN — possible system prompt override attempt");
        }

        score = Math.min(score, 100);

        if (reason != null) {
            log.warn("INPUT SCAN BLOCKED — reason='{}' score={}", reason, score);
            return ScanResult.detected(reason, blockOnDetection, score);
        }
        return ScanResult.clean(score);
    }

    /** PII detection on the prompt itself, before it's ever sent to the LLM. */
    public PiiScanResult scanForPii(String userMessage) {
        for (PiiPatterns.Redaction pr : PiiPatterns.PATTERNS) {
            if (pr.pattern().matcher(userMessage).find()) {
                if ("BLOCK".equalsIgnoreCase(piiAction)) {
                    log.warn("INPUT SCAN BLOCKED — PII detected in prompt (pattern='{}')", pr.pattern().pattern());
                    return PiiScanResult.blocked("PII detected in prompt");
                }
                String redacted = pr.pattern().matcher(userMessage).replaceAll(pr.replacement());
                for (PiiPatterns.Redaction next : PiiPatterns.PATTERNS) {
                    redacted = next.pattern().matcher(redacted).replaceAll(next.replacement());
                }
                log.info("INPUT SCAN — PII redacted from prompt before sending to LLM");
                return PiiScanResult.redacted(redacted);
            }
        }
        return PiiScanResult.clean(userMessage);
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /** Returns the decoded payload if any Base64-looking chunk decodes to a known injection pattern, else null. */
    private String findBase64InjectionPayload(String text) {
        String b64Pattern = "[A-Za-z0-9+/]{40,}={0,2}";
        var matcher = Pattern.compile(b64Pattern).matcher(text);
        while (matcher.find()) {
            try {
                String decoded = new String(Base64.getDecoder().decode(matcher.group()));
                for (Pattern p : INJECTION_PATTERNS) {
                    if (p.matcher(decoded).find()) {
                        return decoded;
                    }
                }
            } catch (IllegalArgumentException ignored) {
                // Not valid base64 — continue
            }
        }
        return null;
    }

    private boolean looksLikeSystemPromptOverride(String userMessage, String systemPrompt) {
        // If user message is longer than system prompt and contains keyword-heavy content
        // that duplicates or contradicts the system prompt, flag it.
        String lower = userMessage.toLowerCase();
        return userMessage.length() > systemPrompt.length() * 2
            && (lower.contains("your instructions are") || lower.contains("new instructions"));
    }

    private String preview(String text) {
        return text.length() > 80 ? text.substring(0, 80) + "..." : text;
    }

    // ── Result types ──────────────────────────────────────────────────────

    public record ScanResult(boolean detected, String reason, boolean shouldBlock, int jailbreakScore) {
        static ScanResult clean(int score) { return new ScanResult(false, null, false, score); }
        static ScanResult detected(String reason, boolean block, int score) {
            return new ScanResult(true, reason, block, score);
        }
        public boolean isDetected() { return detected; }
        public boolean shouldBlock() { return shouldBlock; }
    }

    public record PiiScanResult(boolean blocked, String content, String reason) {
        static PiiScanResult clean(String content) { return new PiiScanResult(false, content, null); }
        static PiiScanResult redacted(String content) { return new PiiScanResult(false, content, "PII redacted from prompt"); }
        static PiiScanResult blocked(String reason) { return new PiiScanResult(true, null, reason); }
        public boolean isBlocked() { return blocked; }
    }
}

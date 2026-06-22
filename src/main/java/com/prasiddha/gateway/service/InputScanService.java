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

    // ── Injection patterns ────────────────────────────────────────────────

    private static final List<Pattern> INJECTION_PATTERNS = List.of(

        // Instruction override
        Pattern.compile("ignore (all |previous |prior |above |the )?(instructions?|prompts?|directives?|rules?|constraints?)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard (all |previous |prior |above |the )?(instructions?|prompts?|directives?|rules?)", Pattern.CASE_INSENSITIVE),
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

    public ScanResult scan(String userMessage, String systemPrompt) {
        if (!enabled) {
            return ScanResult.clean();
        }

        // 1. Check for Base64-encoded injection payloads
        ScanResult base64Result = checkBase64Encoding(userMessage);
        if (base64Result.isDetected()) return base64Result;

        // 2. Check direct pattern matches
        for (Pattern pattern : INJECTION_PATTERNS) {
            if (pattern.matcher(userMessage).find()) {
                String reason = "Injection pattern detected: " + pattern.pattern();
                log.warn("INPUT SCAN BLOCKED — pattern='{}' preview='{}'",
                    pattern.pattern(), preview(userMessage));
                return ScanResult.detected(reason, blockOnDetection);
            }
        }

        // 3. Check if user message is trying to override system prompt
        if (systemPrompt != null && looksLikeSystemPromptOverride(userMessage, systemPrompt)) {
            String reason = "Possible system prompt override attempt";
            log.warn("INPUT SCAN BLOCKED — system prompt override attempt");
            return ScanResult.detected(reason, blockOnDetection);
        }

        return ScanResult.clean();
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private ScanResult checkBase64Encoding(String text) {
        // Look for suspiciously long Base64-looking strings that decode to injection text
        String b64Pattern = "[A-Za-z0-9+/]{40,}={0,2}";
        var matcher = Pattern.compile(b64Pattern).matcher(text);
        while (matcher.find()) {
            try {
                String decoded = new String(Base64.getDecoder().decode(matcher.group()));
                // Recursively scan the decoded content
                for (Pattern p : INJECTION_PATTERNS) {
                    if (p.matcher(decoded).find()) {
                        String reason = "Base64-encoded injection payload detected";
                        log.warn("INPUT SCAN BLOCKED — base64 injection, decoded preview='{}'",
                            preview(decoded));
                        return ScanResult.detected(reason, blockOnDetection);
                    }
                }
            } catch (IllegalArgumentException ignored) {
                // Not valid base64 — continue
            }
        }
        return ScanResult.clean();
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

    // ── Result type ───────────────────────────────────────────────────────

    public record ScanResult(boolean detected, String reason, boolean shouldBlock) {
        static ScanResult clean() { return new ScanResult(false, null, false); }
        static ScanResult detected(String reason, boolean block) {
            return new ScanResult(true, reason, block);
        }
        public boolean isDetected() { return detected; }
        public boolean shouldBlock() { return shouldBlock; }
    }
}

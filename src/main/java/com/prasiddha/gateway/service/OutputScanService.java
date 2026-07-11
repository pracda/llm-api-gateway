package com.prasiddha.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans and sanitises LLM output before returning it to clients.
 * Covers OWASP LLM Top 10 #05 — Improper Output Handling.
 *
 * Checks:
 *   1. Canary token — confirms whether the hardened system prompt leaked (OWASP LLM #06)
 *   2. PII patterns — emails, phone numbers, SSNs, credit card numbers
 *   3. Secret / credential leakage — API keys, tokens, passwords
 *   4. Malicious content — XSS payloads, script injection, SQL injection
 *   5. Competitor mentions — visibility only, never blocks
 *   6. Excessive length — truncate responses above configured limit
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OutputScanService {

    private final CanaryTokenProvider canaryTokenProvider;

    @Value("${app.security.output.sanitisation-enabled}")
    private boolean enabled;

    @Value("${app.security.output.block-on-unsafe-output}")
    private boolean blockOnUnsafe;

    @Value("${app.security.output.max-response-length}")
    private int maxResponseLength;

    @Value("${app.security.competitor-keywords}")
    private String competitorKeywordsCsv;

    // ── Patterns that should BLOCK (dangerous — never return to client) ────

    private static final List<Pattern> BLOCK_PATTERNS = List.of(

        // Script injection / XSS
        Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("javascript:\\s*[^\"'\\s]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("on(load|click|error|mouseover|submit)\\s*=", Pattern.CASE_INSENSITIVE),

        // SQL injection echoed in output
        Pattern.compile("(?i)(DROP TABLE|DELETE FROM|INSERT INTO|UNION SELECT|; ?--)"),

        // Shell command injection signals
        Pattern.compile("(?i)(rm -rf|chmod 777|wget http|curl http.*\\| ?sh|/etc/passwd|/etc/shadow)"),

        // API key / token patterns (common formats)
        Pattern.compile("sk-[a-zA-Z0-9]{40,}"),                             // OpenAI keys
        Pattern.compile("sk-ant-[a-zA-Z0-9\\-_]{80,}"),                     // Anthropic keys
        Pattern.compile("(?i)(api[_-]?key|bearer)[\"'\\s:=]+[a-zA-Z0-9\\-_]{20,}")
    );

    // ── Public API ────────────────────────────────────────────────────────

    public ScanResult scan(String llmOutput) {
        if (!enabled || llmOutput == null || llmOutput.isBlank()) {
            return ScanResult.safe(llmOutput);
        }

        // 1. Canary token — confirmed system-prompt leak, always a hard block regardless of blockOnUnsafe
        String canary = canaryTokenProvider.get();
        if (llmOutput.contains(canary)) {
            log.error("OUTPUT SCAN — canary token detected in output! System prompt leak confirmed.");
            return ScanResult.leaked("System prompt leak detected (canary token present in output)");
        }

        // 2. Check for hard-block patterns
        for (Pattern pattern : BLOCK_PATTERNS) {
            if (pattern.matcher(llmOutput).find()) {
                String reason = "Unsafe content detected in LLM output: " + describePattern(pattern);
                log.warn("OUTPUT SCAN BLOCKED — pattern='{}' (first 100 chars): '{}'",
                    pattern.pattern(), preview(llmOutput));
                return blockOnUnsafe
                    ? ScanResult.blocked(reason)
                    : ScanResult.sanitised("[Content blocked by security policy]", reason, false);
            }
        }

        // 3. Redact PII and sensitive data
        String sanitised = llmOutput;
        boolean wasRedacted = false;

        for (PiiPatterns.Redaction pr : PiiPatterns.PATTERNS) {
            Matcher m = pr.pattern().matcher(sanitised);
            if (m.find()) {
                sanitised = m.replaceAll(pr.replacement());
                wasRedacted = true;
                log.info("OUTPUT SCAN REDACTED — pattern='{}' replacement='{}'",
                    pr.pattern().pattern(), pr.replacement());
            }
        }

        // 4. Competitor mentions — visibility only, never blocks or redacts
        boolean competitorMentioned = false;
        for (String keyword : competitorKeywords()) {
            if (!keyword.isBlank() && sanitised.toLowerCase().contains(keyword.trim().toLowerCase())) {
                competitorMentioned = true;
                log.info("OUTPUT SCAN — competitor mention detected: '{}'", keyword.trim());
                break;
            }
        }

        // 5. Enforce maximum length
        if (sanitised.length() > maxResponseLength) {
            log.info("OUTPUT SCAN TRUNCATED — length={} max={}", sanitised.length(), maxResponseLength);
            sanitised = sanitised.substring(0, maxResponseLength)
                + "\n\n[Response truncated by gateway security policy]";
            wasRedacted = true;
        }

        if (wasRedacted) {
            return ScanResult.sanitised(sanitised, "PII/sensitive data redacted", competitorMentioned);
        }
        return competitorMentioned
            ? ScanResult.safeWithCompetitorMention(sanitised)
            : ScanResult.safe(sanitised);
    }

    private List<String> competitorKeywords() {
        return competitorKeywordsCsv == null || competitorKeywordsCsv.isBlank()
            ? List.of()
            : Arrays.asList(competitorKeywordsCsv.split(","));
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private String preview(String text) {
        return text.length() > 100 ? text.substring(0, 100) + "..." : text;
    }

    private String describePattern(Pattern p) {
        String pat = p.pattern();
        if (pat.contains("script")) return "XSS/script injection";
        if (pat.contains("DROP TABLE")) return "SQL injection echo";
        if (pat.contains("sk-")) return "API key leakage";
        if (pat.contains("rm -rf")) return "Shell command injection";
        return "Unsafe pattern";
    }

    // ── Types ─────────────────────────────────────────────────────────────

    public record ScanResult(
        Status status,
        String content,   // sanitised or null if blocked
        String reason,
        boolean promptLeakDetected,
        boolean competitorMentioned
    ) {
        public boolean isSafe()      { return status == Status.SAFE; }
        public boolean isSanitised() { return status == Status.SANITISED; }
        public boolean isBlocked()   { return status == Status.BLOCKED; }

        static ScanResult safe(String content) {
            return new ScanResult(Status.SAFE, content, null, false, false);
        }
        static ScanResult safeWithCompetitorMention(String content) {
            return new ScanResult(Status.SAFE, content, null, false, true);
        }
        static ScanResult sanitised(String content, String reason, boolean competitorMentioned) {
            return new ScanResult(Status.SANITISED, content, reason, false, competitorMentioned);
        }
        static ScanResult blocked(String reason) {
            return new ScanResult(Status.BLOCKED, null, reason, false, false);
        }
        static ScanResult leaked(String reason) {
            return new ScanResult(Status.BLOCKED, null, reason, true, false);
        }

        public enum Status { SAFE, SANITISED, BLOCKED }
    }
}

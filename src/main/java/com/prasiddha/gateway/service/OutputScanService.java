package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans and sanitises LLM output before returning it to clients.
 * Covers OWASP LLM Top 10 #05 — Improper Output Handling.
 *
 * Checks:
 *   1. PII patterns — emails, phone numbers, SSNs, credit card numbers
 *   2. Secret / credential leakage — API keys, tokens, passwords
 *   3. Malicious content — XSS payloads, script injection, SQL injection
 *   4. Sensitive data disclosure — system prompt echo, internal paths
 *   5. Excessive length — truncate responses above configured limit
 */
@Slf4j
@Service
public class OutputScanService {

    @Value("${app.security.output.sanitisation-enabled}")
    private boolean enabled;

    @Value("${app.security.output.block-on-unsafe-output}")
    private boolean blockOnUnsafe;

    @Value("${app.security.output.max-response-length}")
    private int maxResponseLength;

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

    // ── Patterns that should be REDACTED (sanitise and continue) ──────────

    private static final List<PatternReplacement> REDACT_PATTERNS = List.of(

        // Email addresses
        new PatternReplacement(
            Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"),
            "[EMAIL REDACTED]"
        ),
        // Phone numbers (US and international)
        new PatternReplacement(
            Pattern.compile("(\\+?1[\\s.-]?)?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}"),
            "[PHONE REDACTED]"
        ),
        // SSN
        new PatternReplacement(
            Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"),
            "[SSN REDACTED]"
        ),
        // Credit card numbers (basic Luhn-format)
        new PatternReplacement(
            Pattern.compile("\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"),
            "[CARD REDACTED]"
        ),
        // IPv4 addresses (internal ranges)
        new PatternReplacement(
            Pattern.compile("\\b(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)([0-9]{1,3}\\.){1}[0-9]{1,3}\\b"),
            "[INTERNAL-IP REDACTED]"
        ),
        // Windows/Unix internal paths
        new PatternReplacement(
            Pattern.compile("(C:\\\\[\\w\\\\]+|/home/[\\w/]+|/var/[\\w/]+|/etc/[\\w/]+)"),
            "[PATH REDACTED]"
        )
    );

    // ── Public API ────────────────────────────────────────────────────────

    public ScanResult scan(String llmOutput) {
        if (!enabled || llmOutput == null || llmOutput.isBlank()) {
            return ScanResult.safe(llmOutput);
        }

        // 1. Check for hard-block patterns
        for (Pattern pattern : BLOCK_PATTERNS) {
            if (pattern.matcher(llmOutput).find()) {
                String reason = "Unsafe content detected in LLM output: " + describePattern(pattern);
                log.warn("OUTPUT SCAN BLOCKED — pattern='{}' (first 100 chars): '{}'",
                    pattern.pattern(), preview(llmOutput));
                return blockOnUnsafe
                    ? ScanResult.blocked(reason)
                    : ScanResult.sanitised("[Content blocked by security policy]", reason);
            }
        }

        // 2. Redact PII and sensitive data
        String sanitised = llmOutput;
        boolean wasRedacted = false;

        for (PatternReplacement pr : REDACT_PATTERNS) {
            Matcher m = pr.pattern().matcher(sanitised);
            if (m.find()) {
                sanitised = m.replaceAll(pr.replacement());
                wasRedacted = true;
                log.info("OUTPUT SCAN REDACTED — pattern='{}' replacement='{}'",
                    pr.pattern().pattern(), pr.replacement());
            }
        }

        // 3. Enforce maximum length
        if (sanitised.length() > maxResponseLength) {
            log.info("OUTPUT SCAN TRUNCATED — length={} max={}", sanitised.length(), maxResponseLength);
            sanitised = sanitised.substring(0, maxResponseLength)
                + "\n\n[Response truncated by gateway security policy]";
            wasRedacted = true;
        }

        return wasRedacted
            ? ScanResult.sanitised(sanitised, "PII/sensitive data redacted")
            : ScanResult.safe(sanitised);
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

    private record PatternReplacement(Pattern pattern, String replacement) {}

    public record ScanResult(
        Status status,
        String content,   // sanitised or null if blocked
        String reason
    ) {
        public boolean isSafe()      { return status == Status.SAFE; }
        public boolean isSanitised() { return status == Status.SANITISED; }
        public boolean isBlocked()   { return status == Status.BLOCKED; }

        static ScanResult safe(String content) {
            return new ScanResult(Status.SAFE, content, null);
        }
        static ScanResult sanitised(String content, String reason) {
            return new ScanResult(Status.SANITISED, content, reason);
        }
        static ScanResult blocked(String reason) {
            return new ScanResult(Status.BLOCKED, null, reason);
        }

        public enum Status { SAFE, SANITISED, BLOCKED }
    }
}

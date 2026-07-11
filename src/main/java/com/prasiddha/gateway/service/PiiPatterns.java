package com.prasiddha.gateway.service;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Shared PII regex patterns — used to redact/detect personal data both in
 * LLM output (OutputScanService, OWASP LLM #05) and in the user's prompt
 * before it's sent to the LLM at all (InputScanService).
 */
public final class PiiPatterns {

    private PiiPatterns() {}

    public record Redaction(Pattern pattern, String replacement) {}

    public static final List<Redaction> PATTERNS = List.of(
        new Redaction(
            Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"),
            "[EMAIL REDACTED]"
        ),
        new Redaction(
            Pattern.compile("(\\+?1[\\s.-]?)?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}"),
            "[PHONE REDACTED]"
        ),
        new Redaction(
            Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"),
            "[SSN REDACTED]"
        ),
        new Redaction(
            Pattern.compile("\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"),
            "[CARD REDACTED]"
        ),
        new Redaction(
            Pattern.compile("\\b(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)([0-9]{1,3}\\.){1}[0-9]{1,3}\\b"),
            "[INTERNAL-IP REDACTED]"
        ),
        new Redaction(
            Pattern.compile("(C:\\\\[\\w\\\\]+|/home/[\\w/]+|/var/[\\w/]+|/etc/[\\w/]+)"),
            "[PATH REDACTED]"
        )
    );
}

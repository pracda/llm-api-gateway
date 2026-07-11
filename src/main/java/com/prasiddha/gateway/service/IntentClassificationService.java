package com.prasiddha.gateway.service;

import com.prasiddha.gateway.model.entity.AuditLog.IntentClassification;
import org.springframework.stereotype.Service;

/**
 * Buckets every request into NORMAL / SUSPICIOUS / MALICIOUS purely from
 * signals the gateway already computes elsewhere in the pipeline (block
 * outcomes, lockout state, jailbreak score) — zero new external calls, zero
 * added latency, and never derived from raw prompt/response content
 * (OWASP LLM #06). This gives admins an evidence trail for the manual
 * "block user" action without needing to re-read raw prompts.
 */
@Service
public class IntentClassificationService {

    private static final int MALICIOUS_JAILBREAK_THRESHOLD  = 70;
    private static final int SUSPICIOUS_JAILBREAK_THRESHOLD = 40;

    public record Signals(
        boolean ipBlocked,
        boolean accountLocked,
        boolean inputBlocked,
        boolean outputBlocked,
        int jailbreakScore
    ) {}

    public record Result(IntentClassification classification, String reason) {}

    public Result classify(Signals s) {
        if (s.ipBlocked()) {
            return new Result(IntentClassification.MALICIOUS, "Request blocked: source IP on admin blocklist");
        }
        if (s.accountLocked()) {
            return new Result(IntentClassification.MALICIOUS, "Request blocked: account under active security lockout");
        }
        if (s.inputBlocked()) {
            return new Result(IntentClassification.MALICIOUS, "Input blocked: prompt injection or PII detected");
        }
        if (s.outputBlocked()) {
            return new Result(IntentClassification.MALICIOUS, "Output blocked: unsafe content or prompt-leak detected");
        }
        if (s.jailbreakScore() >= MALICIOUS_JAILBREAK_THRESHOLD) {
            return new Result(IntentClassification.MALICIOUS,
                "Jailbreak risk score " + s.jailbreakScore() + "/100");
        }
        if (s.jailbreakScore() >= SUSPICIOUS_JAILBREAK_THRESHOLD) {
            return new Result(IntentClassification.SUSPICIOUS,
                "Elevated jailbreak risk score " + s.jailbreakScore() + "/100");
        }
        return new Result(IntentClassification.NORMAL, null);
    }
}

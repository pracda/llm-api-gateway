-- Per-request intent verdict (NORMAL/SUSPICIOUS/MALICIOUS), derived from
-- signals the gateway already computes (jailbreak score, block outcomes,
-- lockout state) — never from raw prompt/response content (OWASP LLM #06).
ALTER TABLE audit_logs ADD COLUMN intent_classification VARCHAR(20) NOT NULL DEFAULT 'NORMAL';
ALTER TABLE audit_logs ADD COLUMN intent_reason VARCHAR(200);

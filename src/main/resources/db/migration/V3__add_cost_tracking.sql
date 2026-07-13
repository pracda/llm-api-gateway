-- Dollar-cost tracking per request (derived from token counts + configured
-- per-model pricing, see app.llm.pricing) and an optional daily spend cap
-- per API key, enforced against running spend tracked in Redis.
ALTER TABLE audit_logs ADD COLUMN cost_usd NUMERIC(10,6) NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN daily_budget_usd NUMERIC(10,2);

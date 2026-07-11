-- Baseline snapshot of the schema as it existed before Flyway was introduced
-- (previously managed by Hibernate ddl-auto: update/validate).
--
-- On a brand-new database this migration runs for real and creates every
-- table from scratch. On an existing dev/prod database (already carrying
-- this schema from ddl-auto), spring.flyway.baseline-on-migrate marks this
-- version as already applied instead of re-running it — see application.yml.

CREATE TABLE organizations (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    name       VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE gateway_users (
    id              VARCHAR(255) NOT NULL PRIMARY KEY,
    username        VARCHAR(50) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL,
    enabled         BOOLEAN NOT NULL,
    organization_id VARCHAR(255),
    created_at      TIMESTAMP NOT NULL,
    last_login_at   TIMESTAMP
);
CREATE UNIQUE INDEX idx_user_username ON gateway_users (username);

CREATE TABLE api_keys (
    id                     VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id        VARCHAR(255) NOT NULL,
    username               VARCHAR(255) NOT NULL,
    name                   VARCHAR(100) NOT NULL,
    key_prefix             VARCHAR(20) NOT NULL,
    key_hash               VARCHAR(64) NOT NULL,
    tier                   VARCHAR(20) NOT NULL,
    requests_per_day       INTEGER NOT NULL,
    max_tokens_per_request INTEGER NOT NULL,
    status                 VARCHAR(20) NOT NULL,
    created_at             TIMESTAMP NOT NULL,
    expires_at             TIMESTAMP,
    last_used_at           TIMESTAMP,
    created_by_admin       VARCHAR(255) NOT NULL
);
CREATE UNIQUE INDEX idx_apikey_hash ON api_keys (key_hash);
CREATE INDEX idx_apikey_org  ON api_keys (organization_id);
CREATE INDEX idx_apikey_user ON api_keys (username);

CREATE TABLE security_alerts (
    id                VARCHAR(255) NOT NULL PRIMARY KEY,
    username          VARCHAR(255),
    type              VARCHAR(40) NOT NULL,
    severity          VARCHAR(10) NOT NULL,
    message           VARCHAR(500) NOT NULL,
    auto_lock_applied BOOLEAN NOT NULL,
    acknowledged      BOOLEAN NOT NULL,
    acknowledged_by   VARCHAR(255),
    acknowledged_at   TIMESTAMP,
    created_at        TIMESTAMP NOT NULL
);
CREATE INDEX idx_alert_created      ON security_alerts (created_at);
CREATE INDEX idx_alert_acknowledged ON security_alerts (acknowledged);
CREATE INDEX idx_alert_severity     ON security_alerts (severity);

CREATE TABLE audit_logs (
    id                VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id           VARCHAR(255) NOT NULL,
    prompt_hash       VARCHAR(64) NOT NULL,
    provider          VARCHAR(20) NOT NULL,
    model             VARCHAR(100),
    outcome           VARCHAR(30) NOT NULL,
    block_reason      VARCHAR(200),
    prompt_tokens     INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    latency_ms        BIGINT NOT NULL,
    http_status       INTEGER NOT NULL,
    jailbreak_score   INTEGER NOT NULL DEFAULT 0,
    ip_address        VARCHAR(45),
    api_key_id        VARCHAR(36),
    streamed          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMP NOT NULL
);
CREATE INDEX idx_audit_user    ON audit_logs (user_id);
CREATE INDEX idx_audit_created ON audit_logs (created_at);
CREATE INDEX idx_audit_outcome ON audit_logs (outcome);

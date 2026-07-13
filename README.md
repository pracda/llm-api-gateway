# Secure LLM API Gateway

[![CI / CD](https://github.com/pracda/llm-api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/pracda/llm-api-gateway/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

A multi-tenant API gateway that sits in front of **OpenAI** and **Anthropic**, giving every team that calls an LLM through it centralized security, abuse detection, and usage visibility — without any of them touching a provider key directly.

Instead of calling LLM APIs directly, client apps call this gateway with an issued API key. It handles authentication, rate limiting, prompt-injection and PII defense, threat detection with automatic lockout, per-request intent classification, and full audit logging — then hands back the model's response (or blocks it, with a reason).

---

## Why this exists

Teams that wire LLM calls straight into their apps end up with provider keys scattered across services, no shared rate limiting, no visibility into who's sending what kind of traffic, and no way to react when something looks like abuse. This gateway centralizes all of that behind one place: issue scoped API keys per team, watch every request in real time, and get an evidence trail the moment something looks wrong — before it becomes an incident.

## Features

**Security pipeline (every request)**
- JWT auth for humans (account/org management) and API-key auth for machine traffic — enforced separately, a valid JWT alone is not enough to call `/chat`
- Prompt injection detection with a 0–100 jailbreak risk score (OWASP LLM01)
- Input/output PII detection and redaction — emails, phone numbers, SSNs, card numbers, internal IPs
- Output sanitisation against XSS, SQL/shell injection echoes, and leaked credentials (OWASP LLM05)
- Canary-token system-prompt-leak detection with automatic API key revocation
- Per-user / per-day / global rate limiting (Redis-backed sliding window)
- Sustained-success-volume detection for suspected model-extraction abuse (OWASP LLM10)

**Multi-tenancy & access control**
- Organizations with Trial / Standard / Enterprise API key tiers (rate limits, token caps, expiry)
- Self-service member provisioning — adding a user to an org auto-creates their account, no separate registration step
- Per-user manual block (disable account + revoke all keys) distinct from automatic temporary lockouts

**Threat detection & evidence**
- Automatic, self-re-arming account lockout on repeated injection attempts, output blocks, rate-limit abuse, or login brute-forcing
- Cross-account coordinated-attack correlation (same attack signature from multiple accounts)
- Rule-based intent classification (`NORMAL` / `SUSPICIOUS` / `MALICIOUS`) on every request, derived entirely from signals already computed in the pipeline — **raw prompts and responses are never stored**, only a SHA-256 hash (OWASP LLM06)
- Per-user evidence trail: intent breakdown, token/volume trend, behavioral-deviation flagging, alert history — everything an admin needs before blocking an account
- Opt-in Slack/webhook delivery for high-severity alerts

**Visibility**
- Real-time operations dashboard (Server-Sent Events) — live request feed, risk rankings, attack timeline, IP blocklist management
- Per-organization trend view and activity log
- Downloadable weekly/monthly PDF activity report per organization (per-member request/token/suspicion counts)

**Streaming**
- Token-by-token streaming (`/chat/stream`) with the same security pipeline — output scanning runs post-delivery for streamed responses, since content can't be un-sent, but it still alerts and can auto-revoke the key

## Request pipeline

```
Client
  │
  ▼
┌────────────────────────────────────────────────────────────────┐
│ Auth — JWT (human) or X-API-Key (machine)                      │
├────────────────────────────────────────────────────────────────┤
│ IP blocklist + account lockout check                            │
├────────────────────────────────────────────────────────────────┤
│ Rate limit — per-user / per-day / global (Redis)                │
├────────────────────────────────────────────────────────────────┤
│ Input scan — injection detection, jailbreak score, PII          │
├────────────────────────────────────────────────────────────────┤
│ LLM call — OpenAI or Anthropic                                  │
├────────────────────────────────────────────────────────────────┤
│ Output scan — canary leak, PII redaction, unsafe content         │
├────────────────────────────────────────────────────────────────┤
│ Intent classification — NORMAL / SUSPICIOUS / MALICIOUS         │
├────────────────────────────────────────────────────────────────┤
│ Audit log (async) — SHA-256 prompt hash only, never raw content │
└────────────────────────────────────────────────────────────────┘
  │
  ▼
Response to client  +  live event pushed to the admin dashboard
```

A blocked request short-circuits at whichever stage caught it (429 for rate limits, 400 for injection/PII/unsafe output, 423 for a lockout, 403 for a blocked IP) — it's still logged with the reason and classified for the evidence trail.

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Java 17, Spring Boot 3.2 |
| Security | Spring Security, JJWT |
| LLM providers | OpenAI & Anthropic REST APIs via Spring WebFlux `WebClient` |
| Database | PostgreSQL 16 + Spring Data JPA, schema-versioned with Flyway |
| Cache / rate limit / threat state | Redis 7 |
| PDF reports | Apache PDFBox |
| Docs | SpringDoc OpenAPI (Swagger UI) |
| Dashboard | Single-page vanilla JS + SSE — no frontend build step |
| Infra | Docker, Docker Compose, GitHub Actions CI, plain EC2 deployment scripts |

## Quick start (local)

### Prerequisites
- Java 17+
- Docker & Docker Compose
- An OpenAI and/or Anthropic API key

### 1. Clone and configure
```bash
git clone https://github.com/pracda/llm-api-gateway.git
cd llm-api-gateway
cp .env.example .env
# Edit .env and add your API keys, and a real JWT_SECRET (32+ chars)
```

### 2. Start everything
```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
```
This builds the app image and starts Postgres, Redis, and the gateway together. Flyway migrates the schema automatically on first boot.

### 3. Open the dashboard
Visit `http://localhost:8080/admin-dashboard.html`. Log in with `admin` / the value of `ADMIN_PASSWORD` in your `.env` (defaults to `admin123` if unset — change this before doing anything real with it).

### 4. Or explore the API directly
Swagger UI: `http://localhost:8080/swagger-ui`

## Deploying to AWS

`deploy/aws/` contains a minimal, no-frills deployment to a single EC2 instance (no Elastic Beanstalk, no Auto Scaling Group, no load balancer — intentionally, to keep cost near-zero for a demo/portfolio deployment):

```powershell
cd deploy/aws
./up.ps1      # provisions a fresh EC2 instance, generates secrets, boots the full stack
./status.ps1  # checks health of the running deployment
./down.ps1    # tears it down completely
```

`up.ps1` resolves the latest Amazon Linux AMI and default VPC/subnet dynamically, generates fresh random secrets for everything except your LLM provider keys (pulled from your local `.env`), and prints the dashboard URL and admin password on completion.

## API reference

All admin endpoints require `ROLE_ADMIN`; `/chat` and `/chat/stream` require an API key specifically (a JWT alone returns 403).

**Auth & self-service**
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Public | Create an account |
| POST | `/api/v1/auth/token` | Public | Exchange credentials for a JWT |
| GET | `/api/v1/users/me` | JWT | Your account info |
| GET | `/api/v1/users/me/api-keys` | JWT | Your issued API keys (masked) |

**Gateway**
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/chat` | API key | Send a prompt, get a complete response |
| POST | `/api/v1/chat/stream` | API key | Same, streamed token-by-token (SSE) |
| GET | `/api/v1/health` | JWT | Authenticated health check |
| GET | `/actuator/health` | Public | Plain liveness check (used by Docker/deploy scripts) |

**Admin — dashboard overview**
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/admin/logs` | Paginated audit log, all users |
| GET | `/api/v1/admin/logs/{userId}` | Audit log for one user |
| GET | `/api/v1/admin/stats` | Overall usage statistics |
| GET | `/api/v1/admin/stats/today` | Today's summary |
| GET | `/api/v1/admin/users` | Top users by request count |
| GET | `/api/v1/admin/stream` | Live SSE feed for the dashboard |
| GET | `/api/v1/admin/risk-rankings` | Per-user risk score, highest first |
| GET | `/api/v1/admin/attack-timeline` | Hourly blocked-request counts |

**Admin — organizations, members & API keys**
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/admin/organizations` | Create an organization |
| GET | `/api/v1/admin/organizations` | List organizations |
| GET | `/api/v1/admin/organizations/{id}` | Org detail — members' keys |
| POST | `/api/v1/admin/organizations/{id}/members` | Add a member (auto-provisions the account) |
| GET | `/api/v1/admin/organizations/{id}/logs` | Audit log scoped to this org |
| GET | `/api/v1/admin/organizations/{id}/trend` | Day-bucketed request/token/alert trend |
| GET | `/api/v1/admin/organizations/{id}/report` | Downloadable weekly/monthly PDF report |
| POST | `/api/v1/admin/organizations/{id}/api-keys` | Issue an API key for a member |
| POST | `/api/v1/admin/api-keys/{id}/suspend` | Temporarily suspend a key |
| POST | `/api/v1/admin/api-keys/{id}/resume` | Resume a suspended key |
| DELETE | `/api/v1/admin/api-keys/{id}` | Permanently revoke a key |

**Admin — alerts & IP blocklist**
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/admin/alerts` | Paginated security alerts |
| POST | `/api/v1/admin/alerts/{id}/acknowledge` | Acknowledge an alert |
| GET | `/api/v1/admin/ip-blocks` | List blocked IPs |
| POST | `/api/v1/admin/ip-blocks` | Block an IP |
| DELETE | `/api/v1/admin/ip-blocks/{ip}` | Unblock an IP |

**Admin — per-user evidence trail**
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/admin/users/{username}/unlock` | Clear an automatic lockout |
| GET | `/api/v1/admin/users/{username}/activity` | Evidence trail — intent breakdown, trend, alerts, keys |
| POST | `/api/v1/admin/users/{username}/block` | Permanently block — disables account, revokes all keys |

## Example request

```bash
# 1. Register an admin creates you as an org member (or self-register directly)
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"prasiddha","password":"yourpassword"}'

# 2. An admin issues you an API key via the dashboard or:
#    POST /api/v1/admin/organizations/{id}/api-keys  { "username": "prasiddha", "tier": "TRIAL", "name": "laptop" }

# 3. Call the gateway with the issued key
curl -X POST http://localhost:8080/api/v1/chat \
  -H "X-API-Key: gw_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "OPENAI",
    "model": "gpt-4o-mini",
    "userMessage": "Explain prompt injection in one paragraph."
  }'
```

## OWASP Top 10 for LLM Applications — coverage

| Risk | Status | How |
|---|---|---|
| Prompt Injection | Covered | `InputScanService` — pattern + encoded-payload detection, jailbreak scoring |
| Improper Output Handling | Covered | `OutputScanService` — XSS/SQLi/shell-injection echo blocking |
| Sensitive Information Disclosure | Covered | Prompts/responses never stored (hash only); input/output PII redaction |
| System Prompt Leakage | Covered | Canary-token injection + detection, auto key revocation |
| Unbounded Consumption / Model DoS | Covered | Multi-tier rate limiting, per-key token caps, extraction-volume detection |
| Excessive Agency | Partially applicable | No tool-calling in this gateway; blast radius limited via tiered keys and manual block |
| Supply Chain / Data Poisoning / Misinformation | Out of scope | Not applicable to a proxy gateway that doesn't train or host models |

## Testing

Requires a local Maven install (there's no wrapper checked in) — tests run against an in-memory H2 database, no Docker services needed:

```bash
mvn test
```

71 tests across unit and MockMvc integration suites — input/output scanning, threat detection and lockout logic, API key lifecycle, org/member provisioning, intent classification, PDF report generation, and auth boundary checks (JWT-only vs. API-key access to `/chat`).

## Project structure

```
src/main/java/com/prasiddha/gateway/
├── controller/    # REST endpoints — chat, auth, users, and 5 focused admin controllers
├── service/       # Business logic — scanning, rate limiting, threat detection, reports
├── security/      # JWT + API-key auth filters
├── proxy/         # OpenAI / Anthropic provider clients
├── model/         # Entities, requests, responses
└── repository/    # Spring Data JPA repositories

src/main/resources/
├── db/migration/       # Flyway schema migrations
└── static/             # Admin dashboard (single HTML file, no build step)

deploy/aws/          # Plain-EC2 up/down/status PowerShell scripts
docker/              # Dockerfile + docker-compose.yml (app + Postgres + Redis)
```

## License

MIT

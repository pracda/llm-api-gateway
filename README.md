# Secure LLM API Gateway

A production-grade API gateway that proxies **OpenAI** and **Anthropic** APIs with full security, observability, and control built in.

## What it does

Instead of calling LLM APIs directly, your apps call this gateway. It enforces:

- **JWT / API-key authentication** — only authorised clients get through
- **Rate limiting** — per-user burst and daily caps (Bucket4j + Redis)
- **Input scanning** — prompt injection detection (OWASP LLM Top 10 #01)
- **Output scanning** — response sanitisation (OWASP LLM Top 10 #05)
- **Audit logging** — every request logged asynchronously to PostgreSQL
- **Multi-provider routing** — OpenAI or Anthropic behind one unified API

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Java 17, Spring Boot 3.2 |
| Security | Spring Security, JJWT, Bucket4j |
| LLM providers | OpenAI Java SDK, Anthropic REST (WebClient) |
| Database | PostgreSQL 16 + Spring Data JPA |
| Cache / rate limit | Redis 7 |
| Docs | SpringDoc OpenAPI (Swagger UI) |
| Infra | Docker, Docker Compose, GitHub Actions |

## Quick start

### Prerequisites
- Java 17+
- Docker & Docker Compose
- An OpenAI or Anthropic API key

### 1. Clone and configure
```bash
git clone https://github.com/prasiddhapaudel/llm-api-gateway.git
cd llm-api-gateway
cp .env.example .env
# Edit .env and add your API keys
```

### 2. Start infrastructure
```bash
docker-compose -f docker/docker-compose.yml up postgres redis -d
```

### 3. Run the app
```bash
./mvnw spring-boot:run
```

### 4. Open Swagger UI
Visit `http://localhost:8080/swagger-ui`

## API reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Public | Create account |
| POST | `/api/v1/auth/token` | Public | Get JWT |
| POST | `/api/v1/chat` | JWT | Send prompt to LLM |
| GET | `/api/v1/users/me` | JWT | Your usage stats |
| GET | `/api/v1/admin/logs` | Admin | Audit log viewer |
| GET | `/api/v1/admin/stats` | Admin | Usage dashboard |
| GET | `/actuator/health` | Public | Health check |

## Example request

```bash
# 1. Register
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"prasiddha","password":"yourpassword"}'

# 2. Get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"prasiddha","password":"yourpassword"}' | jq -r .token)

# 3. Call the gateway
curl -X POST http://localhost:8080/api/v1/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "OPENAI",
    "model": "gpt-4o-mini",
    "userMessage": "Explain prompt injection in one paragraph."
  }'
```

## Security model

```
Client → [Auth] → [Rate Limit] → [Input Scan] → LLM → [Output Scan] → Client
                      ↓               ↓                      ↓
                   429 Throttled  400 Blocked            400 Unsafe output
```

All blocked requests are logged with the reason. Raw prompts are never stored — only SHA-256 hashes.

## Running tests

```bash
./mvnw test
```

## License

MIT

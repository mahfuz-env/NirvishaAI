# NirvishaAI — Backend

> AI-powered web security scanner backend. Built with Go.

NirvishaAI scans your verified domain for security vulnerabilities, explains each issue using AI in Bengali, and generates downloadable PDF/Markdown reports.

---

## Features

- **Parallel scanning** — 5 security checks run concurrently via goroutines
- **SSL/TLS check** — certificate validity, expiry, HTTPS redirect
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, X-Content-Type-Options
- **Cookie security** — HttpOnly, Secure, SameSite flag detection
- **CORS misconfiguration** — wildcard and origin reflection detection
- **Open redirect** — tests 9 common redirect parameters
- **AI analysis** — Bengali explanations via OpenRouter (4 fallback models)
- **Domain verification** — DNS TXT record or file-based ownership proof
- **Rate limiting** — 5 scans/day per IP via Redis
- **PDF + Markdown reports** — downloadable scan reports
- **Real-time progress** — Server-Sent Events (SSE) stream

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.22+ |
| Router | chi v5 |
| Cache | Redis (TTL-based, no permanent storage) |
| AI | OpenRouter API |
| PDF | gofpdf (pure Go) |

---

## Project Structure

```
backend/
├── main.go              # Server entry point, routing
├── config/
│   └── config.go        # Env loading
├── store/
│   └── redis.go         # Redis client, key schema, TTL helpers
├── handlers/
│   ├── verify.go        # Domain verification (DNS + file)
│   ├── scan.go          # Scan start, SSE progress, rate limiting
│   ├── report.go        # PDF + Markdown download
│   └── helpers.go       # JSON response helpers
├── scanner/
│   ├── types.go         # Shared types, score calculator
│   ├── runner.go        # Parallel goroutine orchestrator
│   ├── ssl.go           # SSL/TLS + HTTPS redirect
│   ├── headers.go       # Security headers
│   ├── cookies.go       # Cookie flags
│   ├── cors.go          # CORS misconfiguration
│   └── redirect.go      # Open redirect
├── ai/
│   └── openrouter.go    # OpenRouter client, fallback chain, Bengali prompt
└── report/
    ├── pdf.go           # PDF generation
    └── markdown.go      # Markdown generation
```

---

## API Endpoints

```
POST /api/verify/dns        — Start DNS TXT verification
POST /api/verify/file       — Check file-based verification
GET  /api/verify/status     — Get verification status (?domain=example.com)

POST /api/scan/start        — Start a scan (verified domain required)
GET  /api/scan/status/:id   — Real-time SSE stream
GET  /api/scan/result/:id   — Full scan result JSON

POST /api/report/pdf/:id    — Download PDF report
POST /api/report/md/:id     — Download Markdown report

GET  /health                — Health check
```

---

## Getting Started

### Prerequisites

- Go 1.22+
- Redis

### Install & Run

```bash
git clone https://github.com/your-repo/nirvishaai-backend.git
cd nirvishaai-backend

cp .env.example .env
# Fill in your OPENROUTER_API_KEY

go mod download
go run main.go
```

Server starts on `http://localhost:8080`

### Environment Variables

```env
OPENROUTER_API_KEY=          # Required — get from openrouter.ai
OPENROUTER_MODEL=google/gemini-flash-1.5
OPENROUTER_FALLBACK_MODEL_1=openai/gpt-4o-mini
OPENROUTER_FALLBACK_MODEL_2=anthropic/claude-3-haiku
OPENROUTER_FALLBACK_MODEL_3=meta-llama/llama-3.1-8b-instruct:free
OPENROUTER_FALLBACK_MODEL_4=mistralai/mistral-7b-instruct:free
REDIS_URL=redis://localhost:6379
PORT=8080
ALLOWED_ORIGINS=http://localhost:3000
SCAN_TIMEOUT=30
MAX_CONCURRENT_SCANS=10
```

---

## Redis Key Schema

All data is temporary — no permanent storage.

```
scan:{id}              → scan result JSON        TTL: 6 hours
scan:progress:{id}     → scan status string      TTL: 6 hours
verify:{domain}        → verification record     TTL: 24 hours
ratelimit:{ip}         → request count           TTL: 24 hours
```

---

## Security & Legal

- Domain ownership **must be verified** before any scan
- Only **passive, non-intrusive** HTTP checks — no payload injection
- Scan results are **not stored permanently**
- Rate limited to **5 scans per IP per day**

> This tool performs non-intrusive checks only. Always get permission before scanning any domain you do not own.

---

## License

MIT — see [LICENSE](LICENSE)

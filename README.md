<<<<<<< HEAD
# NEURAL-X AI Cyber Defense Platform v2

Enterprise-grade AI-powered Cyber Defense & Journal Authenticity Verification Platform.

## What's New in v2

- **Journal Authenticity Verification** — detect fake journals, predatory publishers, fake conferences
- **Hybrid Scoring Engine** — multi-signal weighted threat score with explainability
- **Academic Database Checks** — live cross-checks against DOAJ, Crossref, OpenAlex
- **Content Analysis** — page-level predatory signal detection, ISSN validation, ethics policy detection
- All v1 features (URL, QR, Image scanning) fully preserved

---

## Quick Start

```bash
git clone <repo>
cd neural-x
cp .env.example .env          # edit SECRET_KEY at minimum
pip install -r requirements.txt
python run.py
# → http://localhost:5000
```

## Folder Structure

```
neural-x/
├── app/
│   ├── __init__.py                  # App factory
│   ├── config.py                    # Config (dev/test/prod) + journal flags
│   ├── blueprints/
│   │   ├── main.py                  # Dashboard
│   │   ├── scanner.py               # URL / QR / Image / Journal scan routes
│   │   ├── api.py                   # REST API endpoints
│   │   ├── admin.py                 # Admin dashboard
│   │   └── history.py               # Scan history
│   ├── models/
│   │   ├── scan_history.py          # v2: adds journal_score, hybrid_score columns
│   │   ├── threat_report.py
│   │   ├── domain_cache.py
│   │   ├── user_account.py
│   │   └── api_usage.py
│   ├── services/
│   │   ├── url_analyzer.py          # URL heuristic analysis (v1, preserved)
│   │   ├── journal_analyzer.py      # [NEW v2] Journal authenticity engine
│   │   ├── hybrid_scorer.py         # [NEW v2] Multi-signal hybrid scoring
│   │   ├── domain_intel.py          # WHOIS / DNS / SSL
│   │   ├── reputation_service.py    # Threat feed integrations
│   │   ├── qr_analyzer.py           # QR decode + analysis
│   │   ├── image_analyzer.py        # Image OCR + threat detection
│   │   ├── screenshot_service.py    # Selenium screenshot
│   │   └── pdf_report.py            # v2: adds journal section to PDF
│   ├── templates/
│   │   ├── scan_journal.html        # [NEW v2] Journal scan form
│   │   ├── result_journal.html      # [NEW v2] Journal result display
│   │   └── ...existing templates preserved...
│   ├── static/
│   │   └── css/neural-x.css        # v2: adds journal/purple theme CSS
│   └── utils/
│       ├── helpers.py               # v2: adds from_json Jinja2 filter
│       └── error_handlers.py
├── tests/
│   └── test_neural_x.py            # v2: adds journal + hybrid scorer tests
├── requirements.txt                 # v2: adds lxml
├── .env.example                     # v2: adds JOURNAL_* config vars
├── Dockerfile
├── docker-compose.yml
└── README.md
=======
# 🛡️ NEURAL-X AI Cyber Defense Platform

A production-grade cybersecurity web platform featuring ML-powered URL threat detection,
QR code intelligence, image forensics, domain intelligence, PDF reporting, and a real-time
security terminal — all wrapped in a futuristic glassmorphism dark UI.

---

## 🚀 Quick Start (Development)

### Prerequisites
- Python 3.10+
- pip
- (Optional) Tesseract OCR: `sudo apt install tesseract-ocr`
- (Optional) Chrome + ChromeDriver for screenshots

### Install & Run

```bash
# 1. Clone / extract project
cd neural-x

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — add API keys if available (optional)

# 5. Run
python run.py
```

Visit: **http://localhost:5000**

---

## 🐳 Docker Deployment (Production)

```bash
# 1. Configure
cp .env.example .env
nano .env   # set SECRET_KEY, DATABASE_URL, API keys

# 2. Build and start
docker-compose up -d --build

# 3. Check logs
docker-compose logs -f neural-x
```

---

## 🔑 API Keys (Optional — falls back gracefully)

| Service | URL | Free Tier |
|---------|-----|-----------|
| Google Safe Browsing | https://developers.google.com/safe-browsing | ✅ Yes |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | ✅ 4 req/min |
| AbuseIPDB | https://www.abuseipdb.com/account/api | ✅ 1000/day |

Add keys to `.env`:
```
GOOGLE_SAFE_BROWSING_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
```

---

## 📡 REST API

All endpoints return JSON.

### Scan URL
```
POST /api/scan-url
Content-Type: application/json

{"url": "https://example.com"}
```

### Scan QR Code
```
POST /api/scan-qr
Content-Type: multipart/form-data

file=<image file>
```

### Scan Image
```
POST /api/scan-image
Content-Type: multipart/form-data

file=<image file>
```

### Get History
```
GET /api/history?page=1&per_page=20&category=Critical+Threat
```

### Get Stats
```
GET /api/stats
```

### Generate PDF Report
```
GET /api/report/<scan_id>
```

---

## 🏗️ Architecture

```
neural-x/
├── run.py                    # App entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── app/
│   ├── __init__.py           # App factory
│   ├── config.py             # Dev/prod/test configs
│   ├── blueprints/
│   │   ├── main.py           # Dashboard routes
│   │   ├── scanner.py        # URL/QR/Image scan routes
│   │   ├── api.py            # REST API endpoints
│   │   ├── admin.py          # Admin dashboard
│   │   └── history.py        # Scan history + export
│   ├── models/
│   │   ├── scan_history.py   # ScanHistory table
│   │   ├── threat_report.py  # ThreatReport table
│   │   ├── domain_cache.py   # DomainCache table
│   │   ├── user_account.py   # UserAccount table
│   │   └── api_usage.py      # APIUsage table
│   ├── services/
│   │   ├── url_analyzer.py   # ML + heuristic URL analysis
│   │   ├── qr_analyzer.py    # QR decode + classify
│   │   ├── image_analyzer.py # OCR + QR + keyword scan
│   │   ├── domain_intel.py   # WHOIS + DNS + SSL
│   │   ├── reputation_service.py # Google SB, VT, URLHaus
│   │   ├── screenshot_service.py # Selenium screenshots
│   │   └── pdf_report.py     # ReportLab PDF generation
│   ├── utils/
│   │   ├── helpers.py        # Utility functions
│   │   └── error_handlers.py # Flask error pages
│   ├── templates/            # Jinja2 HTML templates
│   └── static/
│       ├── css/neural-x.css  # Glassmorphism dark theme
│       └── js/               # Matrix, terminal, app JS
├── docker/
│   └── gunicorn.conf.py
└── nginx/
    └── nginx.conf
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
```

---

<<<<<<< HEAD
## API Reference

### Existing (v1 — unchanged)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan-url` | Analyze a URL for phishing/malware |
| POST | `/api/scan-qr` | Upload QR image for analysis |
| POST | `/api/scan-image` | Upload image for threat scanning |
| GET  | `/api/history` | Paginated scan history |
| GET  | `/api/stats` | Platform statistics |
| GET  | `/api/report/<id>` | Generate PDF for scan |

### New in v2

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan-journal` | Full journal authenticity analysis |
| GET  | `/api/journal-check?url=` | Quick journal legitimacy check |

### Journal API Example

```bash
curl -X POST http://localhost:5000/api/scan-journal \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-journal.com"}'
```

Response:
```json
{
  "status": "success",
  "data": {
    "scan_id": 42,
    "journal_score": 71.5,
    "authenticity_score": 28.5,
    "phishing_probability": 35.2,
    "hybrid_score": 58.1,
    "score_basis": "heuristic-estimate",
    "risk_category": "High Risk",
    "api_checks": {
      "doaj": {"checked": true, "found": false},
      "crossref": {"checked": true, "found": false},
      "openalex": {"checked": true, "found": false}
    },
    "content_findings": {
      "predatory_keywords": ["rapid publication", "guaranteed acceptance"],
      "unverified_indexing_claims": ["scopus indexed"],
      "issns_found": ["1234-5678"],
      "has_contact": false,
      "has_editorial_board": false,
      "has_ethics_policy": false
    },
    "risk_factors": ["..."],
    "recommendations": ["..."],
    "explainability": "Multiple threat indicators detected..."
  }
}
=======
## 🔒 Security Features

- **CSRF protection** on all forms (Flask-WTF)
- **Rate limiting** — 100 req/hour default, 30/min on API scan endpoints
- **Input sanitization** — URL + file validation before processing
- **Secure headers** — X-Frame-Options, X-XSS-Protection, CSP-ready
- **File upload validation** — extension whitelist + 16MB max
- **SQL injection prevention** — SQLAlchemy ORM (no raw SQL)
- **XSS prevention** — Jinja2 auto-escaping enabled

---

## 📊 Database Tables

| Table | Purpose |
|-------|---------|
| `scan_history` | Every scan result with score + category |
| `threat_reports` | Detailed per-scan risk factors + raw API data |
| `domain_cache` | Cached WHOIS/DNS results (reduces API calls) |
| `user_accounts` | Authentication-ready user table |
| `api_usage` | External API call tracking + quota monitoring |

---

## 🧪 Running Tests

```bash
pytest tests/ -v --cov=app
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
```

---

<<<<<<< HEAD
## Score Transparency

All scores in NEURAL-X v2 are labeled as **heuristic estimates** based on observable signals:

- URL structure features, keyword analysis, domain age, SSL validity
- Live cross-checks with DOAJ, Crossref, OpenAlex APIs
- Predatory keyword detection, ISSN validation, content analysis

Scores are **not** derived from a cross-validated ML model with reported accuracy. The `score_basis` field in all API responses is always `"heuristic-estimate"`. Users should independently verify findings using [Think.Check.Submit](https://thinkchecksubmit.org), [DOAJ](https://doaj.org), and [Crossref](https://crossref.org).

---

## Deployment

```bash
# Docker
docker-compose up --build

# Gunicorn (production)
gunicorn -c docker/gunicorn.conf.py "app:create_app('production')"
```

---

## Testing

```bash
pip install pytest pytest-flask
pytest tests/ -v
```

---

## Change Log

### v2.0.0
- **NEW**: `app/services/journal_analyzer.py` — Journal Authenticity Verification Engine
- **NEW**: `app/services/hybrid_scorer.py` — Multi-signal hybrid scoring with explainability
- **NEW**: `app/blueprints/scanner.py` — `/scan/journal` route
- **NEW**: `app/blueprints/api.py` — `/api/scan-journal`, `/api/journal-check`
- **NEW**: `app/templates/scan_journal.html`, `result_journal.html`
- **UPGRADED**: `app/models/scan_history.py` — added `journal_score`, `journal_data`, `hybrid_score`, `phishing_prob` columns (nullable, backwards-compatible)
- **UPGRADED**: `app/services/pdf_report.py` — journal section in PDF output
- **UPGRADED**: `app/utils/helpers.py` — `from_json` Jinja2 filter
- **UPGRADED**: `app/config.py` — `JOURNAL_*` config keys
- **UPGRADED**: `app/static/css/neural-x.css` — journal/purple theme additions
- **UPGRADED**: `requirements.txt` — added `lxml`
- **UPGRADED**: `tests/test_neural_x.py` — journal + hybrid scorer tests
=======
## 📱 Mobile App Integration

The REST API at `/api/*` is designed to support:
- Android (Retrofit / OkHttp)
- Flutter (http / dio)
- React Native (fetch / axios)
- Progressive Web App (PWA)

All responses use consistent `{"status": "success", "data": {...}}` format.

---

## 🚀 Production Checklist

- [ ] Change `SECRET_KEY` in `.env`
- [ ] Set `FLASK_ENV=production`
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS via Nginx + SSL certificate
- [ ] Add API keys for threat feeds
- [ ] Install Tesseract OCR system package
- [ ] Install Chrome + ChromeDriver for screenshots
- [ ] Configure log rotation

---

## 📄 License

NEURAL-X AI Cyber Defense Platform. For educational and informational use.
All threat assessments are advisory only.
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

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
```

---

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
```

---

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

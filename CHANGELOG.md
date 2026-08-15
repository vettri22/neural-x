# NEURAL-X Change Log

## v3.0.0 — AI Website Classification & False-Positive Reduction

### New Files
| File | Description |
|------|-------------|
| `app/services/website_classifier.py` | **AI Website Classifier** — classifies any URL into: `academic_database`, `publisher`, `university`, `government`, `research_org`, `repository`, `journal`, `conference`, `unknown`. Uses exact-match registry (400+ known domains) + TLD heuristics + keyword patterns. Returns `should_run_journal_checks` flag to prevent false positives on Crossref, OpenAlex, DOAJ, etc. |

### Upgraded Files

#### `app/services/journal_analyzer.py` (v3)
- **Step 1 now calls `classify_website()`** before any external API call
- **Known-safe early return**: OpenAlex, Crossref, DOAJ, IEEE, Springer, Wiley, etc. return `is_known_safe=True` immediately — no false-positive risk
- **Parallel API calls**: DOAJ, Crossref, OpenAlex, ROR run concurrently via `ThreadPoolExecutor`
- **ROR integration**: Research Organization Registry added as 4th verification source
- **`NOT_VERIFIED` vs `FAKE`**: when external DBs timeout/fail, status is `not_verified` — never `fake`
- **`VERIFICATION_CONFLICT` detection**: when sources return contradictory results
- **Trust dimensions**: per-axis scores — `website_type`, `publisher`, `domain_trust`, `content_quality`, `index_verification`
- **Positive signals**: alongside risk factors, explicitly tracks what looks legitimate
- **Improved ISSN validation**: full mod-11 checksum check, invalid ISSNs flagged separately
- **Predatory keyword list expanded** to 19 patterns
- **Content analysis**: 12 positive content signal patterns tracked
- **Country extraction**: from ROR or WHOIS
- **Organisation name**: from ROR > DOAJ > Crossref
- `score_basis` always `'heuristic-estimate'`

#### `app/services/hybrid_scorer.py` (v3)
- Separate weight tables for journal scans vs URL scans
- Known-safe floor: final_score ≤ 5 for recognised platforms
- Inherits trust_dimensions, positive_signals, conflicts from journal_result
- Conflict-aware category capping: `High Risk` → `Suspicious` when sources conflict
- Richer explainability including organisation name, website type, verification status

#### `app/blueprints/scanner.py`
- URL route: calls `classify_website()` before `analyze_journal()`, only merges risk factors when `not is_known_safe`
- Journal route: same classification-first pattern

#### `app/blueprints/api.py`
- `/api/scan-journal` response enriched with v3 fields: `website_type`, `website_type_display`, `organisation`, `country`, `is_known_safe`, `trust_dimensions`, `positive_signals`, `conflicts`, `classification_evidence`

#### `app/templates/result_journal.html` (rebuilt)
- **Website Classification card** — icon, display name, organisation, country, evidence chips
- **Conflict banner** — prominent warning when sources disagree
- **Known-safe banner** — green banner for recognised legitimate platforms
- **Trust Breakdown** — 5-dimension colour-coded progress bars
- **DB Verification cards** — DOAJ, Crossref, OpenAlex, ROR with `VERIFIED / NOT FOUND / NOT VERIFIED / SKIPPED` states
- **NOT VERIFIED explanation box** — clarifies this is a connectivity issue, not proof of fakeness
- **AI Explanation panel** — full explainability text
- **Positive Signals section** — explicitly listed alongside risk factors
- **Content Analysis** — 7 content checks, ISSN badges with invalid highlighting
- **Hybrid sub-scores** with weight transparency note

#### `app/templates/scan_journal.html`
- Updated "What We Check" list (16 items including ROR, conflict detection, positive signals)
- Updated Databases panel with ROR entry
- Added "NOT VERIFIED ≠ FAKE" explanation box

#### `app/config.py`
- Added `JOURNAL_ROR_ENABLED`, `JOURNAL_PARALLEL_WORKERS`
- `TestingConfig` disables ROR check alongside other external calls

#### `tests/test_neural_x.py`
- `TestWebsiteClassifier` — 13 tests covering known entities, TLD detection, keyword detection, confidence range
- `TestJournalAnalyzerV3` — 9 tests covering known-safe return, trust dimensions, conflict key, score_basis, NOT_VERIFIED-not-fake rule

---

## v2.0.0 — Journal Authenticity Verification

- Added `app/services/journal_analyzer.py` — DOAJ, Crossref, OpenAlex checks
- Added `app/services/hybrid_scorer.py` — multi-signal weighted scoring
- Added `/scan/journal` route and templates
- Added `/api/scan-journal`, `/api/journal-check` endpoints
- Updated `ScanHistory` model with journal columns
- Updated PDF report with journal section

## v1.0.0 — Initial Release

- URL phishing detection
- QR code intelligence
- Malicious image detection
- Domain intelligence (WHOIS, SSL, DNS)
- Reputation feeds
- Screenshot capture
- PDF reports
- Scan history
- Admin dashboard

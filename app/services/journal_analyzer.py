"""
Journal Authenticity Verification Service — v3
NEURAL-X AI Cyber Defense Platform

Architecture:
  Step 1 — Website classification (never runs journal checks on known databases)
  Step 2 — Parallel external DB checks: DOAJ, Crossref, OpenAlex, ROR
  Step 3 — Domain intelligence signals
  Step 4 — Content analysis (predatory keywords, ISSN, editorial board, ethics)
  Step 5 — Hybrid trust score with per-dimension breakdown
  Step 6 — Explainability: positive signals + risk factors + verification conflicts

Key principles:
  - Never falsely classify OpenAlex/Crossref/DOAJ/known publishers as fake
  - If a source is unreachable, report NOT_VERIFIED — never FAKE
  - When trusted sources disagree, report VERIFICATION_CONFLICT
  - Every score backed by observable evidence
  - Score basis always labelled 'heuristic-estimate'
"""

import re
import json
import logging
import urllib.parse
import concurrent.futures
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

# ── Request tuning ────────────────────────────────────────────────────────────
_DEFAULT_TIMEOUT   = 10   # overridden by Flask config JOURNAL_REQUEST_TIMEOUT
_PARALLEL_WORKERS  = 4    # max threads for parallel API calls

# ── Regex patterns ────────────────────────────────────────────────────────────
ISSN_PATTERN = re.compile(r'\b(\d{4})-(\d{3}[\dXx])\b')
DOI_PATTERN  = re.compile(r'\b10\.\d{4,9}/[^\s"<>]+')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

# ── Predatory signals ─────────────────────────────────────────────────────────
PREDATORY_KEYWORDS: List[str] = [
    'rapid publication', 'fast publication', 'quick publication',
    'publish in days', 'accepted within', 'guaranteed acceptance',
    'no peer review', 'waive peer review', 'pay after acceptance',
    'indexed in all major databases', 'impact factor guaranteed',
    'highly cited journal', 'scopus indexed guaranteed',
    'free of cost publication', 'publish for free',
    'no publication fee', 'article processing charge waived',
    'special issue discount', 'invitation to publish',
]

FAKE_INDEXING_SIGNALS: List[str] = [
    'indexed by scopus', 'scopus indexed', 'web of science indexed',
    'wos indexed', 'scie indexed', 'ssci indexed', 'impact factor',
    'sci expanded', 'emerging sources citation index',
    'esci listed', 'jcr listed',
]

SCAM_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.online', '.site', '.website', '.space', '.fun', '.icu', '.buzz',
}

# ── Trust signals (negative indicators for legitimate sites) ──────────────────
POSITIVE_CONTENT_SIGNALS: List[Tuple[str, str]] = [
    ('editorial board',   'Editorial board listed'),
    ('editor-in-chief',   'Editor-in-Chief named'),
    ('peer review',       'Peer review process described'),
    ('publication ethics','Publication ethics statement present'),
    ('plagiarism',        'Plagiarism policy present'),
    ('cope',              'COPE membership mentioned'),
    ('retraction',        'Retraction policy present'),
    ('open access policy','Open access policy defined'),
    ('author guidelines', 'Author guidelines available'),
    ('copyright',         'Copyright information present'),
    ('issn',              'ISSN mentioned on page'),
    ('doi',               'DOI system referenced'),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_timeout() -> int:
    try:
        from flask import current_app
        return int(current_app.config.get('JOURNAL_REQUEST_TIMEOUT', _DEFAULT_TIMEOUT))
    except RuntimeError:
        return _DEFAULT_TIMEOUT


def _config_flag(key: str, default: bool = True) -> bool:
    try:
        from flask import current_app
        return bool(current_app.config.get(key, default))
    except RuntimeError:
        return default


def _parse_domain(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url if '://' in url else 'https://' + url)
        host = parsed.netloc.split(':')[0].lower().lstrip('www.')
        return host
    except Exception:
        return url.lower()


def _apex(domain: str) -> str:
    parts = domain.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain


def _ua() -> str:
    return 'NEURAL-X/3.0 (AI Cyber Defense; research tool; mailto:research@neural-x.ai)'


# ── External API checks ───────────────────────────────────────────────────────

def _check_doaj(domain: str) -> Dict[str, Any]:
    """
    Query DOAJ journal search API.
    Returns: {status, found, title, publisher, issn, works_count, error}
    status: 'found' | 'not_found' | 'not_verified' | 'disabled'
    """
    if not _config_flag('JOURNAL_DOAJ_ENABLED'):
        return {'status': 'disabled', 'found': False, 'source': 'DOAJ'}

    out = {'status': 'not_verified', 'found': False, 'source': 'DOAJ',
           'title': None, 'publisher': None, 'issn': None, 'error': None}
    try:
        q = urllib.parse.quote(domain)
        r = requests.get(
            f'https://doaj.org/api/search/journals/{q}?pageSize=1',
            timeout=_get_timeout(), headers={'User-Agent': _ua()}
        )
        r.raise_for_status()
        data = r.json()
        results = data.get('results', [])
        if results:
            bib = results[0].get('bibjson', {})
            issns = bib.get('identifier', [])
            out.update({
                'status':    'found',
                'found':     True,
                'title':     bib.get('title', ''),
                'publisher': bib.get('publisher', {}).get('name', ''),
                'issn':      ', '.join(i.get('id', '') for i in issns
                                       if i.get('type') in ('pissn', 'eissn')),
                'is_oa':     True,
            })
        else:
            out['status'] = 'not_found'
    except requests.exceptions.Timeout:
        out['error'] = 'Request timed out'
        out['status'] = 'not_verified'
    except requests.exceptions.ConnectionError:
        out['error'] = 'Connection failed'
        out['status'] = 'not_verified'
    except Exception as e:
        out['error'] = str(e)[:120]
        out['status'] = 'not_verified'
        logger.debug(f'DOAJ check failed for {domain}: {e}')
    return out


def _check_crossref(domain: str) -> Dict[str, Any]:
    """Query Crossref members API for publisher registration."""
    if not _config_flag('JOURNAL_CROSSREF_ENABLED'):
        return {'status': 'disabled', 'found': False, 'source': 'Crossref'}

    out = {'status': 'not_verified', 'found': False, 'source': 'Crossref',
           'member_name': None, 'doi_prefix': None, 'error': None}
    try:
        q = urllib.parse.quote(domain)
        r = requests.get(
            f'https://api.crossref.org/members?query={q}&rows=3',
            timeout=_get_timeout(), headers={'User-Agent': _ua()}
        )
        r.raise_for_status()
        data = r.json()
        items = data.get('message', {}).get('items', [])
        # Filter: member's primary-name or location should relate to our domain
        for item in items:
            name = item.get('primary-name', '')
            prefixes = item.get('prefixes', [])
            # Loose match: domain apex appears in the publisher name
            if _apex(domain).split('.')[0].lower() in name.lower():
                out.update({
                    'status':      'found',
                    'found':       True,
                    'member_name': name,
                    'doi_prefix':  prefixes[0] if prefixes else None,
                    'works_count': item.get('counts', {}).get('total-dois', 0),
                })
                break
        if not out['found'] and items:
            # Broader: any hit from the query
            item = items[0]
            out.update({
                'status':      'found_broad',
                'found':       False,       # broad match — not confirmed
                'member_name': item.get('primary-name', ''),
                'doi_prefix':  (item.get('prefixes') or [None])[0],
            })
        elif not items:
            out['status'] = 'not_found'
    except requests.exceptions.Timeout:
        out.update({'error': 'Request timed out', 'status': 'not_verified'})
    except requests.exceptions.ConnectionError:
        out.update({'error': 'Connection failed', 'status': 'not_verified'})
    except Exception as e:
        out.update({'error': str(e)[:120], 'status': 'not_verified'})
        logger.debug(f'Crossref check failed: {e}')
    return out


def _check_openalex(domain: str) -> Dict[str, Any]:
    """Query OpenAlex sources API."""
    if not _config_flag('JOURNAL_OPENALEX_ENABLED'):
        return {'status': 'disabled', 'found': False, 'source': 'OpenAlex'}

    out = {'status': 'not_verified', 'found': False, 'source': 'OpenAlex',
           'display_name': None, 'works_count': 0, 'is_oa': False, 'error': None}
    try:
        q = urllib.parse.quote(domain)
        r = requests.get(
            f'https://api.openalex.org/sources?search={q}&per-page=3',
            timeout=_get_timeout(), headers={'User-Agent': _ua()}
        )
        r.raise_for_status()
        data  = r.json()
        results = data.get('results', [])
        apex_d = _apex(domain).split('.')[0].lower()
        for src in results:
            name = (src.get('display_name') or '').lower()
            host = (src.get('host_organization_name') or '').lower()
            if apex_d in name or apex_d in host:
                out.update({
                    'status':       'found',
                    'found':        True,
                    'display_name': src.get('display_name', ''),
                    'works_count':  src.get('works_count', 0),
                    'is_oa':        src.get('is_oa', False),
                    'publisher':    src.get('host_organization_name', ''),
                })
                break
        if not out['found']:
            if results:
                out.update({
                    'status':       'not_found',
                    'searched':     True,
                    'top_result':   results[0].get('display_name', ''),
                })
            else:
                out['status'] = 'not_found'
    except requests.exceptions.Timeout:
        out.update({'error': 'Request timed out', 'status': 'not_verified'})
    except requests.exceptions.ConnectionError:
        out.update({'error': 'Connection failed', 'status': 'not_verified'})
    except Exception as e:
        out.update({'error': str(e)[:120], 'status': 'not_verified'})
        logger.debug(f'OpenAlex check failed: {e}')
    return out


def _check_ror(domain: str) -> Dict[str, Any]:
    """Query Research Organization Registry (ROR) for institution verification."""
    out = {'status': 'not_verified', 'found': False, 'source': 'ROR',
           'name': None, 'country': None, 'org_type': None, 'error': None}
    try:
        q = urllib.parse.quote(_apex(domain).split('.')[0])
        r = requests.get(
            f'https://api.ror.org/organizations?query={q}&page=1',
            timeout=_get_timeout(), headers={'User-Agent': _ua()}
        )
        r.raise_for_status()
        data  = r.json()
        items = data.get('items', [])
        apex_d = _apex(domain).split('.')[0].lower()
        for item in items:
            links = [l.lower() for l in (item.get('links') or [])]
            aliases = [a.lower() for a in (item.get('aliases') or [])]
            name = (item.get('name') or '').lower()
            if any(apex_d in l for l in links) or apex_d in name:
                out.update({
                    'status':   'found',
                    'found':    True,
                    'name':     item.get('name', ''),
                    'country':  item.get('country', {}).get('country_name', ''),
                    'org_type': ', '.join(item.get('types', [])),
                    'ror_id':   item.get('id', ''),
                })
                break
        if not out['found']:
            out['status'] = 'not_found'
    except Exception as e:
        out.update({'error': str(e)[:120], 'status': 'not_verified'})
        logger.debug(f'ROR check failed: {e}')
    return out


def _fetch_page(url: str, max_chars: int = 20000) -> Tuple[str, str]:
    """
    Fetch page content.
    Returns (text_lower, final_url). text_lower is '' on failure.
    """
    if not _config_flag('JOURNAL_CONTENT_SCAN'):
        return '', url
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        from app.utils.ssrf_guard import validate_public_url
        ok, reason = validate_public_url(url)
        if not ok:
            logger.info(f'Journal page fetch blocked ({reason}): {url}')
            return '', url
        r = requests.get(
            url, timeout=_get_timeout(),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
                'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
            allow_redirects=True,
        )
        final_url = r.url
        # Lightweight HTML stripping
        text = re.sub(r'<!--.*?-->', ' ', r.text, flags=re.DOTALL)
        text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>',  ' ', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text[:max_chars].lower(), final_url
    except Exception as e:
        logger.debug(f'Page fetch failed {url}: {e}')
        return '', url


def _check_infra(domain: str) -> Dict[str, bool]:
    """Check robots.txt and sitemap.xml availability."""
    result = {'robots': False, 'sitemap': False}
    t = min(_get_timeout(), 5)
    for path, key in [('/robots.txt', 'robots'), ('/sitemap.xml', 'sitemap')]:
        try:
            r = requests.get(f'https://{domain}{path}', timeout=t, allow_redirects=True)
            result[key] = r.status_code == 200 and len(r.text.strip()) > 20
        except Exception:
            pass
    return result


# ── ISSN validation ───────────────────────────────────────────────────────────

def _validate_issn(issn_str: str) -> Tuple[bool, str]:
    """Validate ISSN-8 checksum. Returns (valid, reason)."""
    digits = issn_str.replace('-', '').upper()
    if len(digits) != 8:
        return False, 'Wrong length'
    total = 0
    for i, ch in enumerate(digits[:7]):
        if not ch.isdigit():
            return False, 'Non-digit in first 7 characters'
        total += int(ch) * (8 - i)
    check = (11 - total % 11) % 11
    expected = 'X' if check == 10 else str(check)
    if digits[7] == expected:
        return True, 'Valid checksum'
    return False, f'Checksum mismatch (expected {expected}, got {digits[7]})'


# ── Verification conflict detection ──────────────────────────────────────────

def _detect_conflicts(doaj: Dict, crossref: Dict, openalex: Dict) -> List[str]:
    """
    Return list of conflict descriptions when trusted sources disagree.
    E.g. DOAJ found it but OpenAlex explicitly not found with high confidence.
    """
    conflicts = []
    found_set  = {s['source'] for s in [doaj, crossref, openalex] if s.get('found')}
    nfound_set = {s['source'] for s in [doaj, crossref, openalex]
                  if s.get('status') == 'not_found'}
    if found_set and nfound_set:
        conflicts.append(
            f'Verification conflict: found in {", ".join(sorted(found_set))} '
            f'but not in {", ".join(sorted(nfound_set))}. '
            f'Results shown as VERIFICATION_CONFLICT.'
        )
    return conflicts


# ── Trust dimension scoring ───────────────────────────────────────────────────

def _score_domain_trust(domain_info: Optional[Dict]) -> Tuple[float, List[str], List[str]]:
    """
    Returns (trust_pct 0-100, positive_signals, risk_factors).
    Higher trust_pct = more trustworthy.
    """
    if not domain_info:
        return 30.0, [], ['Domain intelligence unavailable']
    positive, risk = [], []
    score = 50.0

    age = domain_info.get('domain_age_days')
    if age is None:
        risk.append('Domain age unknown')
        score -= 15
    elif age > 3650:
        positive.append(f'Established domain ({age // 365}+ years old)')
        score += 20
    elif age > 730:
        positive.append(f'Mature domain ({age // 365} years old)')
        score += 10
    elif age < 180:
        risk.append(f'Very new domain ({age} days old)')
        score -= 25
    elif age < 365:
        risk.append(f'Domain less than 1 year old ({age} days)')
        score -= 12

    ssl = domain_info.get('ssl', {})
    if ssl.get('valid'):
        positive.append('Valid SSL/TLS certificate')
        score += 15
        days = ssl.get('days_remaining', 999)
        if days < 14:
            risk.append(f'SSL certificate expires in {days} days')
            score -= 10
    else:
        risk.append('No valid SSL certificate')
        score -= 25

    if domain_info.get('whois', {}).get('available'):
        positive.append('WHOIS records available')
        score += 5
    else:
        risk.append('WHOIS data unavailable or hidden')
        score -= 10

    return round(max(0.0, min(100.0, score)), 1), positive, risk


def _score_publisher_verification(doaj: Dict, crossref: Dict,
                                  openalex: Dict, ror: Dict,
                                  is_known_safe: bool) -> Tuple[float, List[str], List[str]]:
    """
    Returns (trust_pct 0-100, positive_signals, risk_factors).
    """
    if is_known_safe:
        return 98.0, ['Recognised in NEURAL-X trusted publisher registry'], []

    positive, risk = [], []
    score = 30.0   # start low — raise on positive evidence

    not_verified_count = 0
    for db in [doaj, crossref, openalex, ror]:
        src = db.get('source', '')
        st  = db.get('status', 'not_verified')
        if st == 'found':
            positive.append(f'✓ Verified in {src}')
            score += 20
        elif st == 'not_found':
            risk.append(f'Not found in {src}')
            score -= 5
        elif st == 'not_verified':
            not_verified_count += 1
        elif st == 'disabled':
            pass   # not penalised for disabled checks

    if not_verified_count == 4:
        risk.append('All database checks returned NOT VERIFIED (connectivity issue?)')
        # Do not penalise further — we cannot confirm fake

    return round(max(0.0, min(100.0, score)), 1), positive, risk


def _score_content_quality(page_text: str, predatory_hits: List[str],
                            unverified_indexing: List[str],
                            issns_found: List[str],
                            issn_invalid: List[str]) -> Tuple[float, List[str], List[str]]:
    if not page_text:
        return 50.0, [], ['Page content could not be retrieved for analysis']

    positive, risk = [], []
    score = 50.0

    for pattern, desc in POSITIVE_CONTENT_SIGNALS:
        if pattern in page_text:
            positive.append(desc)
            score += 3
    score = min(score, 90.0)

    if predatory_hits:
        risk.append(f'Predatory publisher signals: {", ".join(predatory_hits[:4])}')
        score -= min(len(predatory_hits) * 6, 30)

    if unverified_indexing:
        risk.append(f'Unverifiable indexing claims: {", ".join(unverified_indexing[:3])}')
        score -= min(len(unverified_indexing) * 8, 25)

    if issns_found:
        positive.append(f'ISSN present on page: {", ".join(issns_found[:3])}')
        score += 5
    else:
        risk.append('No ISSN number found on page')
        score -= 10

    if issn_invalid:
        risk.append(f'Invalid ISSN checksum detected: {", ".join(issn_invalid)}')
        score -= 15

    return round(max(0.0, min(100.0, score)), 1), positive, risk


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_journal(url: str, domain_info: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Comprehensive journal authenticity analysis — v3.

    Pipeline:
      1. Classify website type
      2. Parallel external DB checks (DOAJ, Crossref, OpenAlex, ROR)
      3. Domain intelligence scoring
      4. Content analysis
      5. Hybrid trust score
      6. Explainability generation

    Returns the full analysis dict. Never fabricates results.
    """
    from app.services.website_classifier import classify_website

    scanned_at = datetime.utcnow().isoformat()
    domain     = _parse_domain(url)

    # ── Step 1: Classify website ───────────────────────────────────────────
    classification = classify_website(url)
    is_known_safe  = classification.get('is_known_safe', False)
    should_journal = classification.get('should_run_journal_checks', True)
    wtype          = classification.get('website_type', 'unknown')
    display_name   = classification.get('display_name', 'Unknown Website')

    # ── Early return for recognised safe platforms ─────────────────────────
    if is_known_safe:
        org = classification.get('organisation', display_name)
        return {
            'url':              url,
            'domain':           domain,
            'website_type':     wtype,
            'website_type_display': display_name,
            'organisation':     org,
            'is_known_safe':    True,
            'journal_score':    2.0,
            'authenticity_score': 98.0,
            'risk_category':    'Safe',
            'risk_factors':     [],
            'positive_signals': classification.get('positive_trust_signals', []) + [
                f'Recognised as: {display_name}',
                'Present in NEURAL-X curated trust registry',
            ],
            'trust_dimensions': {
                'website_type':    98.0,
                'publisher':       98.0,
                'domain_trust':    98.0,
                'content_quality': None,   # not scanned — not needed
                'index_verification': None,
            },
            'api_checks':        {'doaj': {'status': 'skipped', 'reason': 'Known safe platform'},
                                  'crossref': {'status': 'skipped'},
                                  'openalex': {'status': 'skipped'},
                                  'ror': {'status': 'skipped'}},
            'content_findings':  {},
            'conflicts':         [],
            'recommendations':   ['This is a recognised legitimate platform. No action required.'],
            'explainability':    _explain_known_safe(classification),
            'classification_evidence': classification.get('evidence', []),
            'scan_type':        'journal',
            'scanned_at':       scanned_at,
            'score_basis':      'heuristic-estimate',
        }

    # ── Step 2: Parallel external DB checks ───────────────────────────────
    api_results: Dict[str, Dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=_PARALLEL_WORKERS) as ex:
        futures = {
            'doaj':     ex.submit(_check_doaj, domain),
            'crossref': ex.submit(_check_crossref, domain),
            'openalex': ex.submit(_check_openalex, domain),
            'ror':      ex.submit(_check_ror, domain),
        }
        for key, fut in futures.items():
            try:
                api_results[key] = fut.result(timeout=_get_timeout() + 2)
            except Exception as e:
                api_results[key] = {
                    'status': 'not_verified', 'found': False,
                    'source': key.upper(), 'error': str(e)[:80],
                }

    doaj      = api_results['doaj']
    crossref  = api_results['crossref']
    openalex  = api_results['openalex']
    ror       = api_results['ror']

    # ── Step 3: Domain intelligence ───────────────────────────────────────
    domain_trust, domain_pos, domain_risk = _score_domain_trust(domain_info)

    # Domain-level red flags
    domain_risk_flags: List[str] = list(domain_risk)
    domain_pos_flags:  List[str] = list(domain_pos)

    for tld in SCAM_TLDS:
        if domain.endswith(tld):
            domain_risk_flags.append(f'Suspicious TLD "{tld}" — rare for legitimate journals')
            domain_trust = max(0, domain_trust - 20)

    # Homograph check
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        domain_risk_flags.append('Non-ASCII domain — possible homograph/Unicode attack')
        domain_trust = max(0, domain_trust - 25)

    # Typosquatting
    brand_names = ['elsevier', 'springer', 'wiley', 'taylor', 'oxford',
                   'cambridge', 'ieee', 'nature', 'science']
    from app.services.website_classifier import KNOWN_PUBLISHERS
    from app.services.website_classifier import _apex as _wa
    for brand in brand_names:
        if brand in _apex(domain) and _apex(domain) not in {_wa(k) for k in KNOWN_PUBLISHERS}:
            domain_risk_flags.append(f'Brand name "{brand}" in domain — possible typosquatting')
            domain_trust = max(0, domain_trust - 20)
            break

    # ── Step 4: Content analysis ──────────────────────────────────────────
    page_text, final_url = _fetch_page(url)
    redirect_flagged = False
    if final_url and final_url.rstrip('/').lower() != url.rstrip('/').lower():
        final_domain = _parse_domain(final_url)
        if final_domain != domain:
            domain_risk_flags.append(f'URL redirects to different domain: {final_domain}')
            redirect_flagged = True

    predatory_hits    = [kw for kw in PREDATORY_KEYWORDS if kw in page_text]
    unverified_index  = []
    if page_text:
        claims = [c for c in FAKE_INDEXING_SIGNALS if c in page_text]
        # Only flag as unverified if DB checks could run and didn't confirm
        can_verify = (doaj.get('status') != 'disabled' or
                      crossref.get('status') != 'disabled' or
                      openalex.get('status') != 'disabled')
        if claims and can_verify:
            if not doaj.get('found') and not crossref.get('found') and not openalex.get('found'):
                unverified_index = claims

    # ISSN extraction and validation
    raw_issns  = ISSN_PATTERN.findall(page_text)
    issns_found   = [f'{a}-{b}' for a, b in raw_issns[:8]]
    issns_invalid = []
    for issn in issns_found[:5]:
        valid, _ = _validate_issn(issn)
        if not valid:
            issns_invalid.append(issn)

    # DOIs and emails
    dois_found   = DOI_PATTERN.findall(page_text)[:5]
    emails_found = EMAIL_PATTERN.findall(page_text)[:5]

    # Content score
    content_trust, content_pos, content_risk = _score_content_quality(
        page_text, predatory_hits, unverified_index, issns_found, issns_invalid
    )

    # Infrastructure
    infra = _check_infra(domain)
    if infra['robots'] or infra['sitemap']:
        domain_pos_flags.append('Site has robots.txt / sitemap.xml — maintained infrastructure')
    else:
        domain_risk_flags.append('No robots.txt or sitemap.xml found')

    # ── Step 5: Publisher verification score ──────────────────────────────
    pub_trust, pub_pos, pub_risk = _score_publisher_verification(
        doaj, crossref, openalex, ror, is_known_safe
    )

    # ── Step 5b: Verification conflicts ───────────────────────────────────
    conflicts = _detect_conflicts(doaj, crossref, openalex)

    # ── Step 5c: Website type trust ───────────────────────────────────────
    wtype_trust_map = {
        'academic_database': 95.0,
        'publisher':         85.0,
        'university':        80.0,
        'government':        90.0,
        'research_org':      75.0,
        'repository':        80.0,
        'journal':           50.0,
        'conference':        50.0,
        'unknown':           30.0,
    }
    wtype_trust = wtype_trust_map.get(wtype, 40.0)

    # ── Step 6: Weighted final journal_score (0=legit, 100=fake) ──────────
    # Invert trust scores → threat contribution
    threat_domain    = 100.0 - domain_trust
    threat_publisher = 100.0 - pub_trust
    threat_content   = 100.0 - content_trust
    threat_wtype     = 100.0 - wtype_trust

    # Weights
    w_domain    = 0.25
    w_publisher = 0.35
    w_content   = 0.25
    w_wtype     = 0.15

    if not page_text:
        # Redistribute content weight
        w_domain    += 0.10
        w_publisher += 0.10
        w_wtype     += 0.05
        w_content    = 0.0

    journal_score = (
        threat_domain    * w_domain +
        threat_publisher * w_publisher +
        threat_content   * w_content +
        threat_wtype     * w_wtype
    )
    journal_score = round(max(0.0, min(100.0, journal_score)), 1)
    authenticity_score = round(100.0 - journal_score, 1)

    # Risk category from journal score
    if journal_score < 20:
        risk_category = 'Safe'
    elif journal_score < 45:
        risk_category = 'Suspicious'
    elif journal_score < 70:
        risk_category = 'High Risk'
    else:
        risk_category = 'Critical Threat'

    # If conflicts detected, cap at Suspicious
    if conflicts and risk_category == 'High Risk':
        risk_category = 'Suspicious'

    # ── Aggregate signals ─────────────────────────────────────────────────
    all_risk    = domain_risk_flags + pub_risk + content_risk
    all_positive = (
        classification.get('positive_trust_signals', []) +
        domain_pos_flags +
        pub_pos +
        content_pos
    )

    # Deduplicate
    def _dedup(lst):
        seen = set(); out = []
        for x in lst:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    all_risk     = _dedup(all_risk)
    all_positive = _dedup(all_positive)

    # ── Recommendations ───────────────────────────────────────────────────
    recs = _build_recommendations(risk_category, wtype, doaj, crossref, conflicts)

    # ── Build full result ─────────────────────────────────────────────────
    return {
        'url':              url,
        'domain':           domain,
        'website_type':     wtype,
        'website_type_display': display_name,
        'organisation':     ror.get('name') or doaj.get('publisher') or crossref.get('member_name') or '',
        'country':          ror.get('country') or (domain_info or {}).get('whois', {}).get('registrant_country', ''),
        'is_known_safe':    False,
        'journal_score':    journal_score,
        'authenticity_score': authenticity_score,
        'risk_category':    risk_category,
        'risk_factors':     all_risk,
        'positive_signals': all_positive,
        'conflicts':        conflicts,
        'trust_dimensions': {
            'website_type':       round(wtype_trust, 1),
            'publisher':          round(pub_trust, 1),
            'domain_trust':       round(domain_trust, 1),
            'content_quality':    round(content_trust, 1) if page_text else None,
            'index_verification': round(pub_trust, 1),   # same evidence base
        },
        'api_checks': {
            'doaj':     doaj,
            'crossref': crossref,
            'openalex': openalex,
            'ror':      ror,
        },
        'content_findings': {
            'predatory_keywords':       predatory_hits,
            'unverified_indexing_claims': unverified_index,
            'issns_found':              issns_found,
            'issns_invalid':            issns_invalid,
            'dois_found':               dois_found,
            'emails_found':             emails_found,
            'has_contact':              any(k in page_text for k in ['contact', 'contact us', 'email us']),
            'has_editorial_board':      'editorial board' in page_text or 'editor-in-chief' in page_text,
            'has_ethics_policy':        any(k in page_text for k in ['publication ethics', 'cope', 'plagiarism']),
            'has_peer_review':          'peer review' in page_text or 'peer-reviewed' in page_text,
            'has_author_guidelines':    'author guidelines' in page_text or 'instructions for authors' in page_text,
            'has_robots':               infra['robots'],
            'has_sitemap':              infra['sitemap'],
            'redirect_detected':        redirect_flagged,
            'final_url':                final_url if redirect_flagged else None,
        },
        'recommendations':       recs,
        'explainability':        _build_explainability(
            wtype, display_name, classification, risk_category,
            journal_score, doaj, crossref, openalex, ror, conflicts,
            all_risk, all_positive
        ),
        'classification_evidence': classification.get('evidence', []),
        'scan_type':        'journal',
        'scanned_at':       scanned_at,
        'score_basis':      'heuristic-estimate',
    }


def _build_recommendations(risk_category, wtype, doaj, crossref, conflicts) -> List[str]:
    recs = []
    if conflicts:
        recs.append(
            'Verification sources disagree — do not rely solely on this report. '
            'Check DOAJ (doaj.org), Crossref (crossref.org), and the publisher website directly.'
        )
    if risk_category in ('High Risk', 'Critical Threat'):
        recs += [
            'Do NOT submit manuscripts or pay fees without independent verification.',
            'Check Think.Check.Submit (thinkchecksubmit.org) before proceeding.',
            'Verify ISSN at portal.issn.org and publisher at crossref.org.',
            "If you suspect a predatory journal, report it to your institution's library.",
        ]
    elif risk_category == 'Suspicious':
        recs += [
            'Proceed with caution — verify independently before submitting.',
            'Confirm journal is listed in DOAJ (doaj.org) or Crossref (crossref.org).',
            'Contact the publisher directly using an email found on an official source, not this website.',
        ]
    else:
        recs.append(
            'Journal appears legitimate based on available signals. '
            'Always verify specific indexing claims directly with the indexing body.'
        )
    recs.append('Never pay publication fees before independently confirming journal authenticity.')
    return recs


def _explain_known_safe(classification: Dict) -> str:
    display = classification.get('display_name', '')
    wtype   = classification.get('website_type', '')
    org     = classification.get('organisation', display)
    return (
        f'Website Type: {display}. '
        f'Organisation: {org}. '
        f'Result: Verified {wtype.replace("_"," ").title()}. '
        f'Reason: Exact match in NEURAL-X curated trust registry. '
        f'This is a recognised legitimate {wtype.replace("_", " ")} — '
        f'journal authenticity checks do not apply.'
    )


def _build_explainability(wtype, display_name, classification, risk_category,
                           journal_score, doaj, crossref, openalex, ror,
                           conflicts, risk_factors, positive_signals) -> str:
    parts = [
        f'Website Type: {display_name}.',
    ]
    if classification.get('evidence'):
        parts.append(f'Classification basis: {"; ".join(classification["evidence"][:3])}.')

    if wtype not in ('journal', 'conference', 'unknown'):
        parts.append(
            f'Note: This site was classified as a {wtype.replace("_"," ")} — '
            f'journal-specific scoring has limited applicability.'
        )

    db_summary = []
    for db in [doaj, crossref, openalex, ror]:
        src = db.get('source', '')
        st  = db.get('status', '')
        if st == 'found':
            db_summary.append(f'{src}: FOUND')
        elif st == 'not_found':
            db_summary.append(f'{src}: NOT FOUND')
        elif st == 'not_verified':
            db_summary.append(f'{src}: NOT VERIFIED (connectivity issue)')
        elif st in ('disabled', 'skipped'):
            pass
    if db_summary:
        parts.append(f'Database verification: {"; ".join(db_summary)}.')

    if conflicts:
        parts.append(f'⚠ VERIFICATION CONFLICT: {conflicts[0]}')

    if positive_signals:
        parts.append(f'Positive signals: {"; ".join(positive_signals[:4])}.')

    if risk_factors:
        parts.append(f'Risk factors: {"; ".join(risk_factors[:4])}.')

    parts.append(
        f'Overall assessment: {risk_category} '
        f'(heuristic journal risk score: {journal_score}/100). '
        f'Scores are observable-signal heuristics, not validated ML accuracy figures.'
    )
    return ' '.join(parts)


# ── Convenience: does this URL warrant journal analysis? ──────────────────────

def is_journal_url(url: str) -> bool:
    """
    Quick check: should we run journal analysis on this URL?
    Yes for journals/conferences/unknown. No for known databases/publishers (handled by classifier).
    """
    try:
        from app.services.website_classifier import classify_website
        c = classify_website(url)
        return c.get('should_run_journal_checks', True)
    except Exception:
        return True

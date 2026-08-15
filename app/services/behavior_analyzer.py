"""
Behavioral Website Analyzer
============================
Feature 2 of the NEURAL-X v4 upgrade.

Safely inspects a webpage's structural/behavioral characteristics WITHOUT
executing any scripts found on the page. We only ever parse HTML text and
inspect the HTTP redirect chain returned by `requests`. No JavaScript
engine, no headless browser execution of the target's scripts, no eval.

Safety measures:
  - SSRF guard on the initial URL and re-validated on every redirect hop
  - Hard timeout on the whole request
  - Redirect count capped
  - Response body capped in size
  - Any failure degrades gracefully — never raises out of analyze_behavior()
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from app.utils.ssrf_guard import validate_public_url

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8
MAX_REDIRECTS = 6
MAX_HTML_BYTES = 1_500_000

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

SUSPICIOUS_JS_PATTERNS = [
    (re.compile(r'document\.write\s*\(', re.IGNORECASE), 'document.write() usage'),
    (re.compile(r'\beval\s*\(', re.IGNORECASE), 'eval() usage'),
    (re.compile(r'unescape\s*\(', re.IGNORECASE), 'unescape() obfuscation'),
    (re.compile(r'fromCharCode', re.IGNORECASE), 'String.fromCharCode obfuscation'),
    (re.compile(r'window\.location\s*=', re.IGNORECASE), 'forced client-side redirect'),
    (re.compile(r'onbeforeunload', re.IGNORECASE), 'page-exit trap (onbeforeunload)'),
    (re.compile(r'oncontextmenu\s*=\s*["\']?return\s*false', re.IGNORECASE), 'right-click disabled'),
]

DOWNLOAD_EXT_PATTERN = re.compile(
    r'href=["\'][^"\']+\.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1)(["\'\?])', re.IGNORECASE
)


class _RedirectGuardError(Exception):
    pass


def _safe_get_with_guarded_redirects(url: str) -> requests.Response:
    """
    Follow redirects manually (instead of requests' allow_redirects=True) so
    that EVERY hop — not just the first URL — is re-validated by the SSRF
    guard before it is fetched.
    """
    session = requests.Session()
    current_url = url
    hops = 0

    while True:
        ok, reason = validate_public_url(current_url)
        if not ok:
            raise _RedirectGuardError(f'Blocked redirect target ({reason}): {current_url}')

        resp = session.get(
            current_url, timeout=REQUEST_TIMEOUT, allow_redirects=False,
            headers={'User-Agent': UA}, stream=True,
        )

        if resp.is_redirect or resp.is_permanent_redirect:
            hops += 1
            if hops > MAX_REDIRECTS:
                raise _RedirectGuardError('Too many redirects (possible redirect loop)')
            next_url = resp.headers.get('Location')
            if not next_url:
                return resp
            if next_url.startswith('/'):
                parsed = urlparse(current_url)
                next_url = f'{parsed.scheme}://{parsed.netloc}{next_url}'
            current_url = next_url
            continue

        return resp


def analyze_behavior(url: str) -> Dict[str, Any]:
    """
    Run the behavioral analysis pipeline.

    Returns:
      {
        'available':          bool,
        'behavior_score':     float | None,
        'indicators':         List[str],
        'redirect_count':     int,
        'final_url':          str | None,
        'unavailable_reason': str | None,
      }
    """
    result: Dict[str, Any] = {
        'available': False,
        'behavior_score': None,
        'indicators': [],
        'redirect_count': 0,
        'final_url': None,
        'unavailable_reason': None,
    }

    ok, reason = validate_public_url(url)
    if not ok:
        result['unavailable_reason'] = f'URL blocked before behavioral analysis: {reason}'
        return result

    try:
        resp = _safe_get_with_guarded_redirects(url)
        html_bytes = resp.raw.read(MAX_HTML_BYTES, decode_content=True)
        html = html_bytes.decode(resp.encoding or 'utf-8', errors='ignore')
        redirect_count = len(resp.history) if hasattr(resp, 'history') else 0
        final_url = resp.url
    except _RedirectGuardError as e:
        result['unavailable_reason'] = str(e)
        return result
    except requests.exceptions.Timeout:
        result['unavailable_reason'] = 'Request timed out during behavioral analysis'
        return result
    except Exception as e:
        result['unavailable_reason'] = f'Behavioral analysis failed: {e}'
        return result

    result['available'] = True
    result['final_url'] = final_url

    score, indicators = _score_page(html, redirect_count, url, final_url)
    result['behavior_score'] = round(min(100.0, score), 1)
    result['indicators'] = indicators or ['No suspicious behavioral indicators detected']
    result['redirect_count'] = redirect_count

    return result


def _score_page(html: str, redirect_count: int, original_url: str, final_url: str):
    score = 0.0
    indicators: List[str] = []

    # 1. Redirect chains
    if redirect_count >= 3:
        score += 25
        indicators.append(f'Multiple redirects detected ({redirect_count} hops)')
    elif redirect_count >= 1:
        score += 10
        indicators.append(f'Redirect detected ({redirect_count} hop{"s" if redirect_count != 1 else ""})')

    orig_domain = urlparse(original_url).netloc
    final_domain = urlparse(final_url).netloc
    if orig_domain and final_domain and orig_domain != final_domain:
        score += 10
        indicators.append(f'Redirected to a different domain ({orig_domain} → {final_domain})')

    # 2. Meta-refresh redirect
    if re.search(r'<meta[^>]+http-equiv=["\']refresh["\']', html, re.IGNORECASE):
        score += 10
        indicators.append('Meta-refresh redirect detected')

    # 3. Password / credential forms
    password_fields = len(re.findall(r'type=["\']password["\']', html, re.IGNORECASE))
    if password_fields:
        score += 20
        indicators.append(f'Password input field(s) detected ({password_fields})')

    # 4. External form submission
    forms = re.findall(r'<form\b[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
    for action in forms:
        if action.startswith('http') and final_domain and final_domain not in action:
            score += 25
            indicators.append(f'Form submits to an external domain ({urlparse(action).netloc})')
            break

    # 5. Suspicious JavaScript behavior (static pattern match only — never executed)
    js_hits = []
    for pattern, label in SUSPICIOUS_JS_PATTERNS:
        if pattern.search(html):
            js_hits.append(label)
    if js_hits:
        score += min(25, 8 * len(js_hits))
        indicators.append('Suspicious script behavior detected: ' + ', '.join(js_hits))

    # 6. iframes (can be used to load hidden phishing content)
    iframe_count = len(re.findall(r'<iframe\b', html, re.IGNORECASE))
    if iframe_count:
        score += min(15, 5 * iframe_count)
        indicators.append(f'{iframe_count} iframe(s) detected on page')

    # 7. Unexpected/executable download links
    downloads = DOWNLOAD_EXT_PATTERN.findall(html)
    if downloads:
        score += 20
        exts = sorted(set(d[0].lower() for d in downloads))
        indicators.append(f'Links to executable/installer files detected ({", ".join(exts)})')

    # 8. Suspicious external resources (script tags pointing off-domain, high count)
    external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    off_domain_scripts = [s for s in external_scripts
                          if s.startswith('http') and final_domain and final_domain not in s]
    if len(off_domain_scripts) > 8:
        score += 10
        indicators.append(f'Unusually high number of external script sources ({len(off_domain_scripts)})')

    return score, indicators

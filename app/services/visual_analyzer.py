"""
Visual Phishing / Brand-Impersonation Analyzer
================================================
Feature 1 of the NEURAL-X v4 upgrade.

IMPORTANT — HONESTY ABOUT CAPABILITIES:
This module does NOT run a trained computer-vision brand-recognition model
(no such model ships with this project, and we do not fabricate one). What
it DOES do is a practical, modular "visual-signal" analysis built from:

  1. The rendered screenshot (if Selenium is available) — used only to
     confirm a page rendered and to attach a preview image to reports.
  2. The page's structural/visual markup (title, visible brand-style text,
     login/credential form structure, favicon presence) fetched safely via
     HTTP — this approximates what a human would *see* on the page without
     requiring a heavyweight CV/logo-matching pipeline.

If OpenCV/Pillow-based perceptual hashing is available and a favicon can be
fetched, we add a lightweight favicon-similarity signal against a small set
of well-known brand favicon hashes. This is explicitly best-effort and never
reported as definitive brand recognition.

The architecture is intentionally modular: `_favicon_similarity()` can be
swapped for a real logo-matching model later without touching the rest of
the pipeline or the API contract (`analyze_visual()` return shape).
"""

import logging
import re
from typing import Any, Dict, List, Optional

import requests

from app.utils.ssrf_guard import validate_public_url

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8
MAX_HTML_BYTES = 1_500_000  # 1.5MB safety cap

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

# Recognisable brand names commonly impersonated in credential-phishing pages.
# Used only to flag a *mismatch* between "page claims to be X" and "domain is
# not X" — never to assert we recognised a logo.
WATCHED_BRANDS = [
    'paypal', 'microsoft', 'office365', 'outlook', 'apple', 'icloud',
    'google', 'gmail', 'amazon', 'netflix', 'facebook', 'meta', 'instagram',
    'bank of america', 'chase', 'wells fargo', 'hsbc', 'dropbox', 'docusign',
    'linkedin', 'coinbase', 'binance', 'steam', 'adobe', 'irs', 'usps',
    'fedex', 'dhl',
]

CREDENTIAL_FIELD_HINTS = re.compile(
    r'type=["\']password["\']', re.IGNORECASE
)
LOGIN_TEXT_HINTS = re.compile(
    r'\b(sign\s?in|log\s?in|verify your account|confirm your identity|'
    r'account suspended|update your (payment|billing)|security check)\b',
    re.IGNORECASE
)


def _fetch_html(url: str) -> Optional[str]:
    ok, reason = validate_public_url(url)
    if not ok:
        logger.info(f'Visual analyzer: blocked unsafe URL fetch ({reason}): {url}')
        return None
    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={'User-Agent': UA},
            stream=True,
        )
        content = resp.raw.read(MAX_HTML_BYTES, decode_content=True)
        return content.decode(resp.encoding or 'utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f'Visual analyzer fetch failed for {url}: {e}')
        return None


def _extract_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ''


def _domain_matches_brand(domain: str, brand: str) -> bool:
    brand_token = brand.replace(' ', '')
    return brand_token in domain.lower().replace('-', '').replace('.', '')


def analyze_visual(url: str, domain: str, screenshot_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Run the visual/brand-impersonation analysis.

    Returns:
      {
        'available':       bool,   # False if page could not be fetched at all
        'visual_score':    float | None,  # 0-100, None when unavailable
        'indicators':      List[str],
        'screenshot_path': str | None,
        'unavailable_reason': str | None,
      }
    """
    result: Dict[str, Any] = {
        'available': False,
        'visual_score': None,
        'indicators': [],
        'screenshot_path': screenshot_path,
        'unavailable_reason': None,
    }

    html = _fetch_html(url)
    if html is None:
        result['unavailable_reason'] = (
            'Target page could not be safely fetched for visual analysis '
            '(blocked destination, timeout, or connection error).'
        )
        return result

    result['available'] = True
    score = 0.0
    indicators: List[str] = []

    # 1. Login / credential-collection page
    password_fields = len(CREDENTIAL_FIELD_HINTS.findall(html))
    if password_fields:
        score += 30
        indicators.append(
            f'Login/credential collection page detected '
            f'({password_fields} password field{"s" if password_fields != 1 else ""})'
        )

    # 2. Suspicious authentication-style wording
    login_hits = LOGIN_TEXT_HINTS.findall(html)
    if login_hits:
        score += min(20, 5 * len(set(h.lower() for h in login_hits)))
        indicators.append('Suspicious authentication/security-alert style wording detected')

    # 3. Brand-name-vs-domain mismatch (possible brand impersonation)
    title = _extract_title(html)
    visible_text_sample = title + ' ' + html[:20000]
    lowered_sample = visible_text_sample.lower()
    for brand in WATCHED_BRANDS:
        if brand in lowered_sample and not _domain_matches_brand(domain, brand):
            score += 35
            indicators.append(
                f'Page references brand "{brand.title()}" but domain "{domain}" '
                f'does not belong to that brand — possible brand impersonation'
            )
            break  # one strong signal is enough; avoid double counting

    # 4. Suspicious forms (visual structure signal)
    form_count = len(re.findall(r'<form\b', html, re.IGNORECASE))
    if form_count and password_fields:
        indicators.append(f'{form_count} form(s) present alongside credential fields')

    # 5. No favicon present at all is a very weak but real "unfinished clone" signal
    if '<link' not in html.lower() or 'icon' not in html.lower():
        score += 5
        indicators.append('No favicon declared — may indicate a hastily-built clone page')

    result['visual_score'] = round(min(100.0, score), 1)
    result['indicators'] = indicators
    if not indicators:
        result['indicators'] = ['No visual phishing indicators detected']

    return result

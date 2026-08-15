"""
URL Threat Analysis Service
Combines ML features + heuristics to compute a 0-100 threat score.
"""

import re
import math
import socket
import urllib.parse
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicious keyword lists
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'confirm', 'password', 'credential', 'banking',
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook',
    'instagram', 'twitter', 'linkedin', 'suspended', 'locked', 'urgent',
    'alert', 'warning', 'limited', 'expire', 'unusual', 'activity',
    'billing', 'invoice', 'refund', 'prize', 'winner', 'free', 'click',
    'download', 'install', 'update-required', 'your-account', 'helpdesk',
]

SCAM_TLD = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
             '.online', '.site', '.website', '.space', '.fun', '.icu'}

BRAND_LIST = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'ebay', 'wellsfargo',
    'bankofamerica', 'chase', 'citibank', 'hsbc', 'barclays',
]

# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _get_domain_parts(url: str) -> Tuple[str, str, str, str]:
    """Return (scheme, netloc, path, full_url_lower)."""
    try:
        parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
        return parsed.scheme, parsed.netloc.lower(), parsed.path, url.lower()
    except Exception:
        return '', '', '', url.lower()


def _count_subdomains(netloc: str) -> int:
    host = netloc.split(':')[0]  # strip port
    parts = host.split('.')
    return max(0, len(parts) - 2)


def _is_ip_url(netloc: str) -> bool:
    host = netloc.split(':')[0]
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    return bool(ip_pattern.match(host))


def _url_length_score(url: str) -> float:
    """Longer URLs are more suspicious. Returns 0-25."""
    length = len(url)
    if length < 54:
        return 0
    elif length < 75:
        return 5
    elif length < 100:
        return 10
    elif length < 150:
        return 15
    else:
        return 25


def _detect_brand_impersonation(netloc: str, path: str) -> Tuple[bool, str]:
    """Check if URL impersonates a known brand."""
    combined = (netloc + path).lower()
    for brand in BRAND_LIST:
        if brand in combined:
            # Domain itself should be the brand's actual domain
            domain_parts = netloc.split('.')
            if len(domain_parts) >= 2:
                apex = domain_parts[-2] + '.' + domain_parts[-1]
                if brand not in apex:
                    return True, brand
    return False, ''


def _count_special_chars(url: str) -> int:
    specials = ['@', '!', '%', '?', '=', '&', '#', '$', '^', '*']
    return sum(url.count(c) for c in specials)


def _detect_obfuscation(url: str) -> bool:
    url_lower = url.lower()
    return (
        '%2f' in url_lower or
        '%40' in url_lower or
        '0x' in url_lower or
        url_lower.count('//') > 1 or
        re.search(r'http.+http', url_lower) is not None
    )


def _detect_typosquatting(netloc: str) -> Tuple[bool, str]:
    """Simple character-substitution typosquat detection."""
    substitutions = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a'}
    host = netloc.split(':')[0].lower()
    normalized = host
    for sub, orig in substitutions.items():
        normalized = normalized.replace(sub, orig)
    if normalized != host:
        for brand in BRAND_LIST:
            if brand in normalized and brand not in host:
                return True, brand
    return False, ''


def _suspicious_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)


def _scam_tld(netloc: str) -> bool:
    for tld in SCAM_TLD:
        if netloc.endswith(tld):
            return True
    return False


def _has_redirect_indicators(url: str) -> bool:
    url_lower = url.lower()
    redirect_patterns = ['redirect', 'redir', 'goto', 'forward', 'url=', 'link=',
                         'out?', 'jump?', 'click?']
    return any(p in url_lower for p in redirect_patterns)


def _entropy(s: str) -> float:
    """Shannon entropy — high entropy subdomains are suspicious."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyze a URL and return a comprehensive threat assessment.

    Returns a dict with:
        threat_score (0-100), risk_category, risk_factors, recommendations,
        feature_scores, metadata
    """
    result: Dict[str, Any] = {
        'url': url,
        'threat_score': 0,
        'risk_category': 'Safe',
        'risk_factors': [],
        'recommendations': [],
        'feature_scores': {},
        'metadata': {},
    }

    if not url or len(url.strip()) < 4:
        result['risk_factors'].append('Invalid or empty URL provided')
        result['threat_score'] = 10
        result['risk_category'] = 'Suspicious'
        return result

    scheme, netloc, path, url_lower = _get_domain_parts(url)
    host = netloc.split(':')[0]

    score = 0.0
    factors = []
    recs = []

    # --- Feature 1: URL length ---
    len_score = _url_length_score(url)
    score += len_score
    if len_score > 0:
        factors.append(f'Unusually long URL ({len(url)} characters)')
    result['feature_scores']['url_length'] = len_score

    # --- Feature 2: IP-based URL ---
    if _is_ip_url(netloc):
        score += 30
        factors.append('URL uses raw IP address instead of domain name')
        recs.append('Avoid visiting IP-based URLs — legitimate services use domain names')
    result['feature_scores']['ip_url'] = 30 if _is_ip_url(netloc) else 0

    # --- Feature 3: Subdomain count ---
    subdomain_count = _count_subdomains(netloc)
    if subdomain_count >= 4:
        score += 20
        factors.append(f'Excessive subdomain depth ({subdomain_count} levels)')
    elif subdomain_count == 3:
        score += 10
        factors.append(f'High subdomain depth ({subdomain_count} levels)')
    result['feature_scores']['subdomain_depth'] = subdomain_count

    # --- Feature 4: Special characters ---
    special_count = _count_special_chars(url)
    if special_count > 10:
        score += 15
        factors.append(f'High special character count ({special_count})')
    result['feature_scores']['special_chars'] = special_count

    # --- Feature 5: Suspicious keywords ---
    kw_count = _suspicious_keyword_count(url)
    kw_score = min(kw_count * 5, 25)
    score += kw_score
    if kw_count > 0:
        factors.append(f'Contains {kw_count} phishing-related keyword(s)')
    result['feature_scores']['keyword_hits'] = kw_count

    # --- Feature 6: Brand impersonation ---
    is_impersonating, brand = _detect_brand_impersonation(netloc, path)
    if is_impersonating:
        score += 35
        factors.append(f'Possible brand impersonation of "{brand}"')
        recs.append(f'This URL may be impersonating {brand}. Verify the official domain before proceeding.')
    result['feature_scores']['brand_impersonation'] = 35 if is_impersonating else 0

    # --- Feature 7: Obfuscation ---
    if _detect_obfuscation(url):
        score += 20
        factors.append('URL contains obfuscation patterns (encoded characters / double slashes)')
        recs.append('URL obfuscation is commonly used in phishing attacks to hide true destinations')
    result['feature_scores']['obfuscation'] = 20 if _detect_obfuscation(url) else 0

    # --- Feature 8: Typosquatting ---
    is_typo, typo_brand = _detect_typosquatting(netloc)
    if is_typo:
        score += 25
        factors.append(f'Possible typosquatting of "{typo_brand}" (character substitution detected)')
        recs.append(f'Domain appears to mimic {typo_brand} using character substitution — classic typosquatting')
    result['feature_scores']['typosquatting'] = 25 if is_typo else 0

    # --- Feature 9: Scam TLD ---
    if _scam_tld(netloc):
        score += 15
        factors.append('Domain uses a TLD commonly associated with free/disposable domains')
    result['feature_scores']['scam_tld'] = 15 if _scam_tld(netloc) else 0

    # --- Feature 10: Redirect indicators ---
    if _has_redirect_indicators(url):
        score += 10
        factors.append('URL contains redirect chain indicators')
        recs.append('Redirect chains can obscure the true destination — trace carefully')
    result['feature_scores']['redirect_chain'] = 10 if _has_redirect_indicators(url) else 0

    # --- Feature 11: HTTPS scheme ---
    if scheme == 'http':
        score += 10
        factors.append('URL uses unencrypted HTTP instead of HTTPS')
        recs.append('Always prefer HTTPS URLs — HTTP transmits data in plaintext')
    result['feature_scores']['no_https'] = 10 if scheme == 'http' else 0

    # --- Feature 12: Entropy of subdomain ---
    subdomain_part = host.rsplit('.', 2)[0] if host.count('.') >= 2 else ''
    entropy = _entropy(subdomain_part)
    if entropy > 4.0:
        score += 15
        factors.append(f'High subdomain entropy ({entropy:.2f}) — may be algorithmically generated')
    result['feature_scores']['domain_entropy'] = round(entropy, 2)

    # --- Feature 13: @ symbol in URL ---
    if '@' in url:
        score += 25
        factors.append('@ symbol in URL — browser ignores everything before @, masking the real destination')
        recs.append('@ in URLs is a classic phishing trick. The real destination is after @.')

    # Cap score at 100
    score = min(100, round(score, 1))
    result['threat_score'] = score

    # Determine risk category
    if score < 20:
        result['risk_category'] = 'Safe'
    elif score < 45:
        result['risk_category'] = 'Suspicious'
    elif score < 70:
        result['risk_category'] = 'High Risk'
    else:
        result['risk_category'] = 'Critical Threat'

    # Default recommendations
    if not recs:
        if score < 20:
            recs.append('No significant threats detected — URL appears safe')
        else:
            recs.append('Exercise caution before visiting this URL')

    recs.append('Always verify the sender before clicking links in emails or messages')
    recs.append('Use a VPN when browsing unfamiliar sites')

    result['risk_factors'] = factors
    result['recommendations'] = recs
    result['metadata'] = {
        'scheme': scheme,
        'host': host,
        'path': path,
        'subdomain_count': subdomain_count,
        'url_length': len(url),
    }

    logger.info(f'URL analyzed: {url[:80]} → score={score} category={result["risk_category"]}')
    return result


def classify_risk(score: float) -> str:
    if score < 20:
        return 'Safe'
    elif score < 45:
        return 'Suspicious'
    elif score < 70:
        return 'High Risk'
    return 'Critical Threat'

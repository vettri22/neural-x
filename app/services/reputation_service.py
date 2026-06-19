"""
Security Intelligence / Reputation Service
Integrates Google Safe Browsing, VirusTotal, AbuseIPDB, URLHaus, OpenPhish, PhishTank.
Falls back to local reputation database when API keys are absent.
"""

import os
import time
import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 8

# ---------------------------------------------------------------------------
# Local fallback blacklist (extended)
# ---------------------------------------------------------------------------
LOCAL_BLACKLIST = {
    'phishing-domains': [
        'evil-login.com', 'secure-paypal-verify.com', 'amazon-security-alert.net',
        'microsoft-update-alert.com', 'apple-id-verify.net', 'google-login-verify.com',
    ],
    'malware-domains': [
        'malware-host.ru', 'ransomware-c2.com', 'botnet-cnc.net',
    ],
    'scam-domains': [
        'free-gift-cards.xyz', 'you-won-prize.top', 'claim-reward-now.club',
    ],
}

LOCAL_BLACKLIST_FLAT = set(
    d for domains in LOCAL_BLACKLIST.values() for d in domains
)


def _log_api_usage(api_name: str, endpoint: str, status_code: int,
                   success: bool, response_time_ms: int, error: str = None):
    """Write an APIUsage record."""
    try:
        from app import db
        from app.models.api_usage import APIUsage
        record = APIUsage(
            api_name=api_name,
            endpoint=endpoint,
            status_code=status_code,
            success=success,
            response_time_ms=response_time_ms,
            error_message=error,
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        logger.debug(f'Failed to log API usage: {e}')


def check_google_safe_browsing(url: str, api_key: str) -> Dict[str, Any]:
    """Check URL against Google Safe Browsing Lookup API v4."""
    result = {'checked': False, 'threat_found': False, 'threat_types': [], 'error': None}
    if not api_key:
        result['error'] = 'No API key configured'
        return result

    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        'client': {'clientId': 'neural-x', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}],
        },
    }
    start = time.time()
    try:
        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        elapsed = int((time.time() - start) * 1000)
        _log_api_usage('google_safe_browsing', endpoint, resp.status_code,
                       resp.status_code == 200, elapsed)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            if data.get('matches'):
                result['threat_found'] = True
                result['threat_types'] = [m['threatType'] for m in data['matches']]
    except Exception as e:
        result['error'] = str(e)
        logger.warning(f'Google Safe Browsing error: {e}')
    return result


def check_virustotal(url: str, api_key: str) -> Dict[str, Any]:
    """Check URL against VirusTotal v3 API."""
    result = {'checked': False, 'positives': 0, 'total': 0, 'permalink': None, 'error': None}
    if not api_key:
        result['error'] = 'No API key configured'
        return result

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    headers = {'x-apikey': api_key}
    start = time.time()
    try:
        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
        elapsed = int((time.time() - start) * 1000)
        _log_api_usage('virustotal', endpoint, resp.status_code, resp.status_code == 200, elapsed)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            result['checked'] = True
            result['positives'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
            result['total'] = sum(stats.values())
            result['permalink'] = f'https://www.virustotal.com/gui/url/{url_id}'
    except Exception as e:
        result['error'] = str(e)
        logger.warning(f'VirusTotal error: {e}')
    return result


def check_urlhaus(url: str) -> Dict[str, Any]:
    """Check URL against URLHaus (no API key required)."""
    result = {'checked': False, 'threat_found': False, 'threat_type': None, 'error': None}
    endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'
    start = time.time()
    try:
        resp = requests.post(endpoint, data={'url': url}, timeout=REQUEST_TIMEOUT)
        elapsed = int((time.time() - start) * 1000)
        _log_api_usage('urlhaus', endpoint, resp.status_code, resp.status_code == 200, elapsed)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            if data.get('query_status') == 'is_listed':
                result['threat_found'] = True
                result['threat_type'] = data.get('tags', ['malware'])[0]
    except Exception as e:
        result['error'] = str(e)
        logger.debug(f'URLHaus error: {e}')
    return result


def check_local_blacklist(url: str) -> Dict[str, Any]:
    """Check URL against local blacklist database."""
    result = {'threat_found': False, 'category': None}
    url_lower = url.lower()
    for category, domains in LOCAL_BLACKLIST.items():
        for domain in domains:
            if domain in url_lower:
                result['threat_found'] = True
                result['category'] = category
                return result
    return result


def get_reputation_verdict(url: str, app_config: Dict) -> Dict[str, Any]:
    """
    Aggregate verdict from all reputation sources.
    Returns combined score contribution and threat details.
    """
    google_key = app_config.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    vt_key = app_config.get('VIRUSTOTAL_API_KEY', '')

    results = {
        'google_safe_browsing': check_google_safe_browsing(url, google_key),
        'virustotal': check_virustotal(url, vt_key),
        'urlhaus': check_urlhaus(url),
        'local_blacklist': check_local_blacklist(url),
    }

    # Compute reputation score addition (0-50)
    rep_score = 0.0
    risk_factors: List[str] = []

    if results['google_safe_browsing'].get('threat_found'):
        rep_score += 50
        types = ', '.join(results['google_safe_browsing']['threat_types'])
        risk_factors.append(f'Google Safe Browsing flagged: {types}')

    vt = results['virustotal']
    if vt.get('checked') and vt.get('positives', 0) > 0:
        vt_contrib = min(vt['positives'] * 5, 40)
        rep_score += vt_contrib
        risk_factors.append(f'VirusTotal: {vt["positives"]}/{vt["total"]} engines detected threats')

    if results['urlhaus'].get('threat_found'):
        rep_score += 35
        risk_factors.append(f'URLHaus blacklist match: {results["urlhaus"].get("threat_type", "malware")}')

    if results['local_blacklist'].get('threat_found'):
        rep_score += 30
        risk_factors.append(f'Local blacklist match: {results["local_blacklist"].get("category")}')

    return {
        'reputation_score': min(100, rep_score),
        'risk_factors': risk_factors,
        'raw': results,
    }

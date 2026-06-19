"""
Domain Intelligence Service
WHOIS, DNS records, SSL certificate analysis, domain age & reputation scoring.
"""

import re
import ssl
import socket
import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def extract_domain(url: str) -> str:
    """Extract apex domain from a URL or hostname."""
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
        host = parsed.netloc.split(':')[0].lower()
        # Remove www.
        if host.startswith('www.'):
            host = host[4:]
        return host
    except Exception:
        return url.lower()


def get_whois_data(domain: str) -> Dict[str, Any]:
    """Fetch WHOIS data for a domain."""
    result = {'domain': domain, 'available': False, 'error': None}
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date

        # Handle list values
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        result['available'] = True
        result['registrar'] = str(w.registrar or 'Unknown')
        result['registrant_country'] = str(w.country or 'Unknown')
        result['creation_date'] = creation_date.isoformat() if creation_date else None
        result['expiration_date'] = expiration_date.isoformat() if expiration_date else None
        result['updated_date'] = updated_date.isoformat() if isinstance(updated_date, datetime) else str(updated_date or '')
        result['name_servers'] = w.name_servers or []
        result['status'] = w.status or []

        # Calculate domain age
        if creation_date and isinstance(creation_date, datetime):
            age = (datetime.now() - creation_date.replace(tzinfo=None))
            result['domain_age_days'] = age.days
        else:
            result['domain_age_days'] = None

    except ImportError:
        result['error'] = 'python-whois not installed'
    except Exception as e:
        result['error'] = str(e)
        logger.warning(f'WHOIS lookup failed for {domain}: {e}')

    return result


def get_dns_records(domain: str) -> Dict[str, Any]:
    """Fetch DNS records (A, MX, NS, TXT) for a domain."""
    records: Dict[str, Any] = {}
    try:
        import dns.resolver
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
    except ImportError:
        # Fallback: basic socket lookup
        try:
            ip = socket.gethostbyname(domain)
            records['A'] = [ip]
        except Exception:
            records['A'] = []
        logger.debug('dnspython not available, used socket fallback')
    except Exception as e:
        logger.warning(f'DNS lookup failed for {domain}: {e}')

    return records


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Check SSL certificate validity and details."""
    result = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'expires': None,
        'days_remaining': None,
        'error': None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['valid'] = True
                result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                result['subject'] = dict(x[0] for x in cert.get('subject', []))
                not_after = cert.get('notAfter', '')
                if not_after:
                    exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result['expires'] = exp.isoformat()
                    result['days_remaining'] = (exp - datetime.utcnow()).days
    except ssl.SSLCertVerificationError as e:
        result['error'] = f'SSL verification failed: {e}'
    except Exception as e:
        result['error'] = str(e)
        logger.debug(f'SSL check failed for {domain}: {e}')
    return result


def calculate_domain_reputation_score(whois_data: Dict, ssl_info: Dict) -> float:
    """
    Calculate a domain reputation risk score (0=good, 100=bad) based on:
    - Domain age
    - SSL validity
    - Registration status
    """
    score = 0.0

    age = whois_data.get('domain_age_days')
    if age is None:
        score += 30  # unknown age is suspicious
    elif age < 30:
        score += 40
    elif age < 180:
        score += 20
    elif age < 365:
        score += 10

    if not ssl_info.get('valid'):
        score += 25

    ssl_days = ssl_info.get('days_remaining')
    if ssl_days is not None and ssl_days < 7:
        score += 15

    if not whois_data.get('available'):
        score += 20

    return min(100, score)


def get_domain_intelligence(url: str) -> Dict[str, Any]:
    """
    Full domain intelligence pipeline.
    Returns WHOIS, DNS, SSL, age, reputation, and risk score.
    """
    domain = extract_domain(url)
    result: Dict[str, Any] = {
        'domain': domain,
        'whois': {},
        'dns': {},
        'ssl': {},
        'reputation_score': 0,
        'domain_age_days': None,
        'risk_factors': [],
    }

    # WHOIS
    whois_data = get_whois_data(domain)
    result['whois'] = whois_data
    result['domain_age_days'] = whois_data.get('domain_age_days')

    # DNS
    result['dns'] = get_dns_records(domain)

    # SSL
    ssl_info = get_ssl_info(domain)
    result['ssl'] = ssl_info

    # Reputation score
    result['reputation_score'] = calculate_domain_reputation_score(whois_data, ssl_info)

    # Risk factors
    age = result['domain_age_days']
    if age is not None and age < 30:
        result['risk_factors'].append(f'Very new domain — registered {age} days ago')
    elif age is not None and age < 180:
        result['risk_factors'].append(f'Recently registered domain — {age} days old')

    if not ssl_info.get('valid'):
        result['risk_factors'].append('No valid SSL certificate found')

    ssl_days = ssl_info.get('days_remaining')
    if ssl_days is not None and ssl_days < 30:
        result['risk_factors'].append(f'SSL certificate expires in {ssl_days} days')

    return result

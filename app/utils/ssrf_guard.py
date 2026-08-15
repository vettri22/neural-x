"""
SSRF Protection Utility
========================
Shared guard used by every service that fetches a user-supplied URL
(behavior analyzer, visual analyzer, journal content fetch, screenshot
service). Resolves the hostname and rejects anything that points at
private / loopback / link-local / multicast / reserved address space,
and rejects non-http(s) schemes.

This is a best-effort mitigation (DNS can still change between check and
connect — "TOCTOU"), so callers should ALSO keep timeouts short and avoid
following unbounded redirect chains. For real production hardening, pin
the resolved IP and connect to it directly; that is out of scope for the
lightweight heuristics scanner here.
"""

import ipaddress
import logging
import socket
import urllib.parse
from typing import Tuple

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = {'http', 'https'}

# Ports we allow the scanner to touch — blocks attempts to use the scanner
# as a generic internal port-scanner (e.g. http://internal-host:6379/).
ALLOWED_PORTS = {80, 443, 8080, 8443}


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable → treat as unsafe

    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or
        ip.is_multicast or ip.is_reserved or ip.is_unspecified or
        (ip.version == 6 and ip.is_site_local)
    )


def validate_public_url(url: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Validate that `url` is a well-formed http(s) URL whose host resolves
    ONLY to public IP addresses.

    Returns (is_safe, reason). If is_safe is False, `reason` explains why
    and the caller MUST NOT fetch the URL.
    """
    if not url or len(url) > 2048:
        return False, 'URL missing or too long'

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, 'URL could not be parsed'

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f'Unsupported scheme: {parsed.scheme!r}'

    host = parsed.hostname
    if not host:
        return False, 'URL has no hostname'

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if port not in ALLOWED_PORTS:
        return False, f'Port {port} not allowed for scanning'

    # Block obvious internal hostnames outright before doing DNS lookups.
    lowered = host.lower()
    if lowered in ('localhost',) or lowered.endswith('.local') or lowered.endswith('.internal'):
        return False, 'Internal/loopback hostname blocked'

    # If host is already a literal IP, validate directly.
    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            return False, 'Target IP is in a private/reserved range'
        return True, 'ok'
    except ValueError:
        pass  # not a literal IP — do DNS resolution below

    try:
        socket.setdefaulttimeout(timeout)
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception as e:
        return False, f'DNS resolution failed: {e}'
    finally:
        socket.setdefaulttimeout(None)

    if not addrinfo:
        return False, 'DNS resolution returned no addresses'

    for family, _, _, _, sockaddr in addrinfo:
        resolved_ip = sockaddr[0]
        if _is_blocked_ip(resolved_ip):
            return False, f'Hostname resolves to a private/reserved address ({resolved_ip})'

    return True, 'ok'

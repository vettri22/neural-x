"""General utility helpers."""

import re
import os


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in allowed_extensions)


def sanitize_url(url: str) -> str:
    """Basic URL sanitization — strip whitespace and null bytes."""
    if not url:
        return ''
    url = url.strip().replace('\x00', '')
    # Ensure scheme present for analysis
    if url and not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    return url


def truncate(s: str, length: int = 80) -> str:
    if not s:
        return ''
    return s if len(s) <= length else s[:length] + '…'


def risk_badge_class(category: str) -> str:
    mapping = {
        'Safe': 'badge-safe',
        'Suspicious': 'badge-suspicious',
        'High Risk': 'badge-high',
        'Critical Threat': 'badge-critical',
    }
    return mapping.get(category, 'badge-unknown')


import json as _json


def register_template_filters(app):
    """Register custom Jinja2 filters."""

    @app.template_filter('from_json')
    def from_json_filter(value):
        """Parse a JSON string in templates: {{ scan.extra_data | from_json }}"""
        if not value:
            return {}
        try:
            return _json.loads(value)
        except Exception:
            return {}

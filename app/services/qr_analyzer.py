"""
QR Code Intelligence Service
Decodes QR content and classifies the payload type.
"""

import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def decode_qr_from_image(image_path: str) -> Optional[str]:
    """
    Attempt to decode a QR code from an image file.
    Uses pyzbar (primary) and falls back to OpenCV QRCodeDetector.
    Returns the decoded string, or None if no QR found.
    """
    # Try pyzbar first
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
        img = Image.open(image_path)
        decoded_objects = pyzbar_decode(img)
        if decoded_objects:
            data = decoded_objects[0].data.decode('utf-8', errors='replace')
            logger.info(f'QR decoded via pyzbar: {data[:80]}')
            return data
    except ImportError:
        logger.debug('pyzbar not available, trying OpenCV')
    except Exception as e:
        logger.warning(f'pyzbar decode error: {e}')

    # Fallback: OpenCV
    try:
        import cv2
        import numpy as np
        from PIL import Image

        img_pil = Image.open(image_path).convert('RGB')
        img_cv = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img_cv)
        if data:
            logger.info(f'QR decoded via OpenCV: {data[:80]}')
            return data
    except Exception as e:
        logger.warning(f'OpenCV QR decode error: {e}')

    return None


def classify_qr_content(content: str) -> Dict[str, Any]:
    """
    Classify the type and meaning of decoded QR content.

    Returns a dict with:
        content_type, display_label, is_url, parsed_data, icon
    """
    if not content:
        return {'content_type': 'empty', 'display_label': 'Empty QR', 'is_url': False,
                'parsed_data': {}, 'icon': '❓'}

    content_stripped = content.strip()

    # --- URL ---
    url_pattern = re.compile(r'^https?://', re.IGNORECASE)
    if url_pattern.match(content_stripped):
        return {
            'content_type': 'url',
            'display_label': 'Web URL',
            'is_url': True,
            'parsed_data': {'url': content_stripped},
            'icon': '🔗',
        }

    # --- Phone number ---
    if re.match(r'^tel:[+\d\s\-()]+$', content_stripped, re.IGNORECASE):
        number = content_stripped[4:]
        return {
            'content_type': 'phone',
            'display_label': 'Phone Number',
            'is_url': False,
            'parsed_data': {'number': number},
            'icon': '📞',
        }

    # --- Email (mailto:) ---
    if re.match(r'^mailto:', content_stripped, re.IGNORECASE):
        email = content_stripped[7:]
        return {
            'content_type': 'email',
            'display_label': 'Email Address',
            'is_url': False,
            'parsed_data': {'email': email},
            'icon': '📧',
        }

    # --- WiFi ---
    if content_stripped.upper().startswith('WIFI:'):
        parsed = _parse_wifi(content_stripped)
        return {
            'content_type': 'wifi',
            'display_label': 'WiFi Network',
            'is_url': False,
            'parsed_data': parsed,
            'icon': '📶',
        }

    # --- vCard / meCard ---
    if content_stripped.upper().startswith('BEGIN:VCARD') or content_stripped.upper().startswith('MECARD:'):
        parsed = _parse_contact(content_stripped)
        return {
            'content_type': 'contact',
            'display_label': 'Contact Card',
            'is_url': False,
            'parsed_data': parsed,
            'icon': '👤',
        }

    # --- Cryptocurrency wallet ---
    crypto_prefixes = ['bitcoin:', 'ethereum:', 'litecoin:', 'dogecoin:', 'monero:']
    if any(content_stripped.lower().startswith(p) for p in crypto_prefixes):
        parts = content_stripped.split(':', 1)
        return {
            'content_type': 'crypto',
            'display_label': 'Cryptocurrency Address',
            'is_url': False,
            'parsed_data': {'currency': parts[0], 'address': parts[1] if len(parts) > 1 else content_stripped},
            'icon': '₿',
        }

    # --- SMS ---
    if re.match(r'^sms:', content_stripped, re.IGNORECASE):
        return {
            'content_type': 'sms',
            'display_label': 'SMS Message',
            'is_url': False,
            'parsed_data': {'raw': content_stripped},
            'icon': '💬',
        }

    # --- Bare URL without scheme ---
    bare_url = re.compile(r'^(www\.|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})(\/.*)?$')
    if bare_url.match(content_stripped):
        full_url = 'http://' + content_stripped
        return {
            'content_type': 'url',
            'display_label': 'Web URL (no scheme)',
            'is_url': True,
            'parsed_data': {'url': full_url},
            'icon': '🔗',
        }

    # --- Plain text fallback ---
    return {
        'content_type': 'text',
        'display_label': 'Plain Text',
        'is_url': False,
        'parsed_data': {'text': content_stripped},
        'icon': '📄',
    }


def _parse_wifi(content: str) -> Dict[str, str]:
    result = {}
    for field, key in [('S:', 'ssid'), ('P:', 'password'), ('T:', 'security')]:
        match = re.search(re.escape(field) + r'([^;]+)', content, re.IGNORECASE)
        if match:
            result[key] = match.group(1)
    return result


def _parse_contact(content: str) -> Dict[str, str]:
    result = {}
    for line in content.splitlines():
        if ':' in line:
            key, _, val = line.partition(':')
            key = key.strip().upper().split(';')[0]
            if key in ('FN', 'N'):
                result['name'] = val.strip()
            elif key in ('TEL', 'TELWORK', 'TELHOME'):
                result['phone'] = val.strip()
            elif key == 'EMAIL':
                result['email'] = val.strip()
            elif key == 'URL':
                result['url'] = val.strip()
    return result


def analyze_qr_image(image_path: str) -> Dict[str, Any]:
    """
    Full QR intelligence pipeline:
    1. Decode QR from image
    2. Classify content type
    3. If URL → trigger phishing analysis
    4. Return comprehensive result
    """
    result: Dict[str, Any] = {
        'qr_found': False,
        'raw_content': None,
        'classification': None,
        'url_analysis': None,
        'risk_factors': [],
        'threat_score': 0,
        'risk_category': 'Safe',
    }

    raw = decode_qr_from_image(image_path)
    if not raw:
        result['risk_factors'].append('No QR code detected in the provided image')
        return result

    result['qr_found'] = True
    result['raw_content'] = raw

    classification = classify_qr_content(raw)
    result['classification'] = classification

    if classification['is_url']:
        from app.services.url_analyzer import analyze_url
        url = classification['parsed_data'].get('url', raw)
        url_result = analyze_url(url)
        result['url_analysis'] = url_result
        result['threat_score'] = url_result['threat_score']
        result['risk_category'] = url_result['risk_category']
        result['risk_factors'] = url_result['risk_factors']
    else:
        # Non-URL content — assess for social-engineering red flags
        content_lower = raw.lower()
        se_keywords = ['urgent', 'password', 'verify', 'free', 'prize', 'winner',
                       'click', 'send', 'transfer', 'bank', 'account']
        hits = [kw for kw in se_keywords if kw in content_lower]
        if hits:
            result['threat_score'] = min(len(hits) * 10, 50)
            result['risk_category'] = 'Suspicious'
            result['risk_factors'].append(f'QR text contains social-engineering keywords: {", ".join(hits)}')
        else:
            result['risk_category'] = 'Safe'

    return result

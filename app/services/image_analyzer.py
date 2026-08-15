"""
Malicious Image Detection Service
Scans uploaded images for hidden QR codes, embedded URLs, OCR text, and social engineering content.
"""

import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

SCAM_KEYWORDS = [
    'urgent', 'password', 'verify', 'account', 'suspended', 'locked',
    'free', 'prize', 'winner', 'click', 'limited', 'expire',
    'confirm', 'update', 'billing', 'invoice', 'refund', 'ssn',
    'social security', 'credit card', 'bank', 'login', 'signin',
    'transfer', 'wire', 'bitcoin', 'crypto', 'gift card',
    'congratulations', 'selected', 'claim', 'reward',
]


def extract_text_ocr(image_path: str) -> str:
    """Extract text from image using pytesseract OCR."""
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        logger.info(f'OCR extracted {len(text)} characters')
        return text
    except ImportError:
        logger.debug('pytesseract not installed — OCR unavailable')
        return ''
    except Exception as e:
        logger.warning(f'OCR extraction error: {e}')
        return ''


def extract_embedded_urls(text: str) -> List[str]:
    """Find all URLs in extracted text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def detect_scam_keywords(text: str) -> List[str]:
    """Return list of scam keywords found in text."""
    text_lower = text.lower()
    return [kw for kw in SCAM_KEYWORDS if kw in text_lower]


def analyze_image_metadata(image_path: str) -> Dict[str, Any]:
    """Extract basic EXIF/metadata from image."""
    meta = {}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(image_path)
        meta['format'] = img.format
        meta['mode'] = img.mode
        meta['size'] = img.size
        exif_data = img._getexif()
        if exif_data:
            meta['exif'] = {TAGS.get(k, k): str(v) for k, v in exif_data.items()
                            if k in TAGS and len(str(v)) < 200}
    except Exception as e:
        logger.debug(f'Metadata extraction error: {e}')
    return meta


def analyze_image(image_path: str) -> Dict[str, Any]:
    """
    Full image security analysis pipeline.
    Returns threat score, risk factors, OCR text, embedded URLs, QR content.
    """
    result: Dict[str, Any] = {
        'ocr_text': '',
        'embedded_urls': [],
        'qr_codes': [],
        'scam_keywords': [],
        'metadata': {},
        'risk_factors': [],
        'recommendations': [],
        'threat_score': 0,
        'risk_category': 'Safe',
    }

    # 1. QR code detection
    try:
        from app.services.qr_analyzer import decode_qr_from_image, classify_qr_content
        qr_content = decode_qr_from_image(image_path)
        if qr_content:
            result['qr_codes'].append(qr_content)
            classification = classify_qr_content(qr_content)
            result['risk_factors'].append(f'Hidden QR code detected in image: {classification["display_label"]}')
            result['threat_score'] += 15
    except Exception as e:
        logger.warning(f'QR detection in image failed: {e}')

    # 2. OCR text extraction
    ocr_text = extract_text_ocr(image_path)
    result['ocr_text'] = ocr_text

    if ocr_text.strip():
        # 3. Embedded URL detection
        embedded_urls = extract_embedded_urls(ocr_text)
        result['embedded_urls'] = embedded_urls
        if embedded_urls:
            result['risk_factors'].append(f'{len(embedded_urls)} URL(s) detected in image text')
            result['threat_score'] += len(embedded_urls) * 10

        # 4. Scam keyword detection
        found_keywords = detect_scam_keywords(ocr_text)
        result['scam_keywords'] = found_keywords
        if found_keywords:
            result['risk_factors'].append(
                f'Social engineering keywords detected: {", ".join(found_keywords[:5])}'
            )
            result['threat_score'] += min(len(found_keywords) * 8, 40)

    # 5. Image metadata
    result['metadata'] = analyze_image_metadata(image_path)

    # 6. Analyze any embedded URLs
    url_analyses = []
    for url in result['embedded_urls'][:3]:  # limit to 3 URLs
        try:
            from app.services.url_analyzer import analyze_url
            url_result = analyze_url(url)
            url_analyses.append(url_result)
            if url_result['threat_score'] > result['threat_score']:
                result['threat_score'] = url_result['threat_score']
        except Exception as e:
            logger.warning(f'URL analysis in image failed for {url}: {e}')

    result['url_analyses'] = url_analyses

    # Cap and classify
    result['threat_score'] = min(100, round(result['threat_score'], 1))
    score = result['threat_score']

    if score < 20:
        result['risk_category'] = 'Safe'
    elif score < 45:
        result['risk_category'] = 'Suspicious'
    elif score < 70:
        result['risk_category'] = 'High Risk'
    else:
        result['risk_category'] = 'Critical Threat'

    # Recommendations
    if result['qr_codes']:
        result['recommendations'].append('Verify the QR code source before scanning with a mobile device')
    if result['embedded_urls']:
        result['recommendations'].append('Do not visit URLs extracted from images without verification')
    if result['scam_keywords']:
        result['recommendations'].append('Image may contain social engineering content — exercise caution')
    if not result['risk_factors']:
        result['recommendations'].append('No threats detected in this image')

    return result

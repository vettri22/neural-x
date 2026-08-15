"""
Website Screenshot Service
Captures headless browser screenshots using Selenium.
Auto-deletes old screenshots, stores only the latest per domain.
"""

import os
import re
import time
import uuid
import logging
import glob
import urllib.parse
from typing import Optional

from app.utils.ssrf_guard import validate_public_url

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                              'app', 'static', 'screenshots')


def _ensure_dir():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def _clean_old_screenshots(prefix: str):
    """Remove previous screenshots for the same domain/prefix."""
    pattern = os.path.join(SCREENSHOT_DIR, f'{prefix}_*.png')
    for f in glob.glob(pattern):
        try:
            os.remove(f)
        except Exception:
            pass


def capture_screenshot(url: str, timeout: int = 15,
                       width: int = 1280, height: int = 720) -> Optional[str]:
    """
    Capture a website screenshot using Selenium.
    Returns the relative path to the saved screenshot, or None on failure.
    """
    full_url = url if '://' in url else 'http://' + url

    # SSRF guard — never point a headless browser at internal infrastructure.
    ok, reason = validate_public_url(full_url)
    if not ok:
        logger.warning(f'Screenshot capture blocked for {url}: {reason}')
        return None

    _ensure_dir()

    # Sanitize domain prefix for filename
    try:
        parsed = urllib.parse.urlparse(full_url)
        domain_prefix = re.sub(r'[^a-zA-Z0-9_\-]', '_', parsed.netloc)[:40]
    except Exception:
        domain_prefix = 'unknown'

    # Clean previous shots for this domain
    _clean_old_screenshots(domain_prefix)

    filename = f'{domain_prefix}_{uuid.uuid4().hex[:8]}.png'
    filepath = os.path.join(SCREENSHOT_DIR, filename)
    relative_path = f'screenshots/{filename}'

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service

        options = Options()
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument(f'--window-size={width},{height}')
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                             'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-logging')
        options.add_argument('--log-level=3')

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(timeout)

        try:
            driver.get(full_url)
            time.sleep(2)  # allow dynamic content to load
            driver.save_screenshot(filepath)
            logger.info(f'Screenshot saved: {filepath}')
            return relative_path
        finally:
            driver.quit()

    except ImportError:
        logger.warning('Selenium not installed — screenshot capture unavailable')
        return None
    except Exception as e:
        logger.warning(f'Screenshot capture failed for {url}: {e}')
        return None

"""
NEURAL-X Configuration Module — v2
Supports development, testing, and production environments.
v2: adds journal-specific config keys.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class BaseConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'neural-x-super-secret-key-change-in-production')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_DIR     = os.path.join(BASE_DIR, 'app', 'static', 'uploads')
    SCREENSHOT_DIR = os.path.join(BASE_DIR, 'app', 'static', 'screenshots')
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_STORAGE_URL = 'memory://'

    # External API keys
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    VIRUSTOTAL_API_KEY           = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY            = os.getenv('ABUSEIPDB_API_KEY', '')

    # Threat scoring weights
    THREAT_SCORE_ML_WEIGHT         = 0.30
    THREAT_SCORE_REPUTATION_WEIGHT = 0.25
    THREAT_SCORE_DOMAIN_WEIGHT     = 0.20
    THREAT_SCORE_SSL_WEIGHT        = 0.10
    THREAT_SCORE_KEYWORDS_WEIGHT   = 0.15

    # Screenshot settings
    SCREENSHOT_TIMEOUT = 15
    SCREENSHOT_WIDTH   = 1280
    SCREENSHOT_HEIGHT  = 720

    HISTORY_PER_PAGE = 20

    # ── v4: Multi-Signal Risk Fusion Engine ─────────────────────────────────
    # Configurable weights for the final 4-signal fusion (URL/ML, Domain,
    # Visual, Behavioral). Must be non-negative; they are re-normalized at
    # runtime, so they don't strictly need to sum to 1.0 — but keeping them
    # summed to 1.0 makes the numbers easy to reason about.
    #
    # Reliability rationale for the defaults:
    #   - url_ml:    0.30  existing URL/ML heuristic model, well-tested, but
    #                      alone insufficient against convincing clones
    #   - domain:    0.20  WHOIS/SSL/age signals are reliable but slow-moving
    #                      (a brand-new malicious domain still needs this)
    #   - visual:    0.20  strong for classic credential-clone pages, weaker
    #                      against pages we can't render or that use no
    #                      recognizable brand text
    #   - behavior:  0.30  redirects/forms/scripts are hard for an attacker
    #                      to fully hide and often the most decisive signal
    RISK_FUSION_WEIGHTS = {
        'url_ml':   float(os.getenv('RISK_WEIGHT_URL_ML', '0.30')),
        'domain':   float(os.getenv('RISK_WEIGHT_DOMAIN', '0.20')),
        'visual':   float(os.getenv('RISK_WEIGHT_VISUAL', '0.20')),
        'behavior': float(os.getenv('RISK_WEIGHT_BEHAVIOR', '0.30')),
    }

    # Final risk-level thresholds (0-100 final fused score)
    RISK_LEVEL_THRESHOLDS = {
        'SAFE':     (0, 29),
        'LOW_MEDIUM': (30, 59),
        'HIGH':     (60, 79),
        'CRITICAL': (80, 100),
    }

    # v3: Website Classifier & Journal Verifier settings
    # Classifier
    WEBSITE_CLASSIFIER_ENABLED = True   # always-on — no API calls involved

    # v2/v3: Journal analyzer settings
    JOURNAL_DOAJ_ENABLED      = os.getenv('JOURNAL_DOAJ_ENABLED', 'true').lower() == 'true'
    JOURNAL_CROSSREF_ENABLED  = os.getenv('JOURNAL_CROSSREF_ENABLED', 'true').lower() == 'true'
    JOURNAL_OPENALEX_ENABLED  = os.getenv('JOURNAL_OPENALEX_ENABLED', 'true').lower() == 'true'
    JOURNAL_CONTENT_SCAN      = os.getenv('JOURNAL_CONTENT_SCAN', 'true').lower() == 'true'
    JOURNAL_REQUEST_TIMEOUT   = int(os.getenv('JOURNAL_REQUEST_TIMEOUT', '10'))
    JOURNAL_ROR_ENABLED       = os.getenv('JOURNAL_ROR_ENABLED', 'true').lower() == 'true'
    JOURNAL_PARALLEL_WORKERS  = int(os.getenv('JOURNAL_PARALLEL_WORKERS', '4'))


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "instance", "neural_x_dev.db")}'
    )
    CACHE_TYPE = 'SimpleCache'


class TestingConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    CACHE_TYPE = 'NullCache'
    # Disable external calls in tests
    JOURNAL_DOAJ_ENABLED     = False
    JOURNAL_CROSSREF_ENABLED = False
    JOURNAL_OPENALEX_ENABLED = False
    JOURNAL_CONTENT_SCAN     = False
    JOURNAL_ROR_ENABLED      = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "instance", "neural_x.db")}'
    )
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE    = True
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)


config_by_name = {
    'development': DevelopmentConfig,
    'testing':     TestingConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig,
}

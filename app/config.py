"""
NEURAL-X Configuration Module
Supports development, testing, and production environments.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class BaseConfig:
    """Base configuration shared across all environments."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'neural-x-super-secret-key-change-in-production')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # File uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_DIR = os.path.join(BASE_DIR, 'app', 'static', 'uploads')
    SCREENSHOT_DIR = os.path.join(BASE_DIR, 'app', 'static', 'screenshots')
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

    # Caching
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

    # Rate limiting
    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_STORAGE_URL = 'memory://'

    # Security APIs
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

    # Threat scoring weights
    THREAT_SCORE_ML_WEIGHT = 0.30
    THREAT_SCORE_REPUTATION_WEIGHT = 0.25
    THREAT_SCORE_DOMAIN_WEIGHT = 0.20
    THREAT_SCORE_SSL_WEIGHT = 0.10
    THREAT_SCORE_KEYWORDS_WEIGHT = 0.15

    # Screenshot settings
    SCREENSHOT_TIMEOUT = 15
    SCREENSHOT_WIDTH = 1280
    SCREENSHOT_HEIGHT = 720

    # Pagination
    HISTORY_PER_PAGE = 20


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


class ProductionConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "instance", "neural_x.db")}'
    )
    CACHE_TYPE = 'SimpleCache'
    WTF_CSRF_ENABLED = True

    # Production security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}

"""
NEURAL-X AI Cyber Defense Platform
Application Factory
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_cors import CORS

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
cache = Cache()


def create_app(config_name=None):
    """Application factory pattern."""
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    from app.config import config_by_name
    cfg = config_by_name.get(config_name or os.getenv('FLASK_ENV', 'development'))
    app.config.from_object(cfg)

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config.get('SCREENSHOT_DIR', 'app/static/screenshots'), exist_ok=True)
    os.makedirs(app.config.get('UPLOAD_DIR', 'app/static/uploads'), exist_ok=True)
    os.makedirs('logs', exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Register blueprints
    from app.blueprints.main import main_bp
    from app.blueprints.scanner import scanner_bp
    from app.blueprints.api import api_bp
    from app.blueprints.admin import admin_bp
    from app.blueprints.history import history_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(scanner_bp, url_prefix='/scan')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(history_bp, url_prefix='/history')

    # Configure security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

    # Configure logging
    if not app.debug:
        handler = RotatingFileHandler('logs/neural-x.log', maxBytes=10240000, backupCount=10)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('NEURAL-X startup')

    # Register template filters
    from app.utils.helpers import register_template_filters
    register_template_filters(app)

    # Register error handlers
    from app.utils.error_handlers import register_error_handlers
    register_error_handlers(app)

    # Create database tables
    with app.app_context():
        db.create_all()

        # v4: additive auto-migration for existing databases (never drops/alters
        # existing columns or rows — see app/utils/db_migrate.py)
        try:
            from app.utils.db_migrate import ensure_new_columns
            from app.models.scan_history import ScanHistory
            ensure_new_columns(db, ScanHistory, [
                ('visual_risk', 'Float'), ('visual_indicators', 'Text'),
                ('behavior_risk', 'Float'), ('behavior_indicators', 'Text'),
                ('domain_risk', 'Float'), ('final_risk_score', 'Float'),
                ('risk_level', 'String'), ('detection_reasons', 'Text'),
                ('prevention_action', 'String'),
            ])
        except Exception as e:
            logging.getLogger(__name__).warning(f'v4 auto-migration skipped: {e}')

    return app

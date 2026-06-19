"""DomainCache — caches expensive WHOIS/DNS lookups."""

from datetime import datetime
from app import db


class DomainCache(db.Model):
    __tablename__ = 'domain_cache'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    whois_data = db.Column(db.Text, nullable=True)
    dns_data = db.Column(db.Text, nullable=True)
    ssl_data = db.Column(db.Text, nullable=True)
    domain_age_days = db.Column(db.Integer, nullable=True)
    registrar = db.Column(db.String(255), nullable=True)
    reputation_score = db.Column(db.Float, default=0.0)
    cached_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)

    def is_expired(self):
        if self.expires_at is None:
            return True
        return datetime.utcnow() > self.expires_at

    def __repr__(self):
        return f'<DomainCache {self.domain}>'

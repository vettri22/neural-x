"""ThreatReport — detailed per-scan threat report stored as JSON."""

from datetime import datetime
from app import db


class ThreatReport(db.Model):
    __tablename__ = 'threat_reports'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)
    ml_score = db.Column(db.Float, default=0.0)
    reputation_score = db.Column(db.Float, default=0.0)
    domain_score = db.Column(db.Float, default=0.0)
    ssl_score = db.Column(db.Float, default=0.0)
    keyword_score = db.Column(db.Float, default=0.0)
    risk_factors = db.Column(db.Text, nullable=True)          # JSON list
    recommendations = db.Column(db.Text, nullable=True)       # JSON list
    whois_data = db.Column(db.Text, nullable=True)            # JSON
    dns_records = db.Column(db.Text, nullable=True)           # JSON
    virustotal_result = db.Column(db.Text, nullable=True)     # JSON
    google_sb_result = db.Column(db.Text, nullable=True)      # JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatReport scan_id={self.scan_id}>'

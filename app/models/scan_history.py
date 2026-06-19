"""ScanHistory model — stores every URL/QR/image scan result."""

from datetime import datetime
from app import db


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=True, index=True)
    domain = db.Column(db.String(255), nullable=True, index=True)
    threat_score = db.Column(db.Float, default=0.0)
    risk_category = db.Column(db.String(50), default='Unknown')  # Safe/Suspicious/High Risk/Critical
    scan_type = db.Column(db.String(50), default='url')          # url / qr / image
    qr_content = db.Column(db.Text, nullable=True)
    domain_age_days = db.Column(db.Integer, nullable=True)
    ssl_valid = db.Column(db.Boolean, nullable=True)
    screenshot_path = db.Column(db.String(512), nullable=True)
    scan_notes = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)          # scanner client IP
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    report = db.relationship('ThreatReport', backref='scan', uselist=False, cascade='all, delete-orphan')

    # JSON blob for extra data (risk factors, recommendations, etc.)
    extra_data = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'domain': self.domain,
            'threat_score': self.threat_score,
            'risk_category': self.risk_category,
            'scan_type': self.scan_type,
            'qr_content': self.qr_content,
            'domain_age_days': self.domain_age_days,
            'ssl_valid': self.ssl_valid,
            'scan_notes': self.scan_notes,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
        }

    def risk_color(self):
        colors = {
            'Safe': '#00ff88',
            'Suspicious': '#ffaa00',
            'High Risk': '#ff6600',
            'Critical Threat': '#ff0044',
        }
        return colors.get(self.risk_category, '#888888')

    def __repr__(self):
        return f'<ScanHistory {self.id} {self.url} {self.risk_category}>'

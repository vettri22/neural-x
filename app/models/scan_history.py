"""ScanHistory model — stores every URL/QR/image/journal scan result."""

from datetime import datetime
from app import db


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id              = db.Column(db.Integer, primary_key=True)
    url             = db.Column(db.String(2048), nullable=True, index=True)
    domain          = db.Column(db.String(255),  nullable=True, index=True)
    threat_score    = db.Column(db.Float,  default=0.0)
    risk_category   = db.Column(db.String(50),   default='Unknown')   # Safe/Suspicious/High Risk/Critical Threat
    scan_type       = db.Column(db.String(50),   default='url')       # url / qr / image / journal
    qr_content      = db.Column(db.Text,   nullable=True)
    domain_age_days = db.Column(db.Integer, nullable=True)
    ssl_valid       = db.Column(db.Boolean, nullable=True)
    screenshot_path = db.Column(db.String(512), nullable=True)
    scan_notes      = db.Column(db.Text,   nullable=True)
    ip_address      = db.Column(db.String(45),  nullable=True)
    scan_date       = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # JSON blob for extra data (risk factors, recommendations, sub-scores …)
    extra_data      = db.Column(db.Text, nullable=True)

    # v2: journal + hybrid scoring columns (nullable — backwards-compatible)
    journal_score   = db.Column(db.Float, nullable=True)   # 0-100, higher = more suspicious journal
    journal_data    = db.Column(db.Text,  nullable=True)   # JSON journal analysis result
    hybrid_score    = db.Column(db.Float, nullable=True)   # Hybrid weighted final score
    phishing_prob   = db.Column(db.Float, nullable=True)   # Heuristic phishing probability (0-100)

    # v4: Visual + Behavioral analysis + final multi-signal fusion (nullable — backwards-compatible)
    visual_risk       = db.Column(db.Float, nullable=True)   # 0-100, None = module unavailable
    visual_indicators = db.Column(db.Text,  nullable=True)   # JSON list
    behavior_risk      = db.Column(db.Float, nullable=True)  # 0-100, None = module unavailable
    behavior_indicators = db.Column(db.Text, nullable=True)  # JSON list
    domain_risk        = db.Column(db.Float, nullable=True)  # 0-100, domain/threat-intel sub-score
    final_risk_score    = db.Column(db.Float, nullable=True) # 0-100, fused final score
    risk_level          = db.Column(db.String(20), nullable=True)  # SAFE/LOW_MEDIUM/HIGH/CRITICAL
    detection_reasons   = db.Column(db.Text, nullable=True)  # JSON list — merged explainability reasons
    prevention_action   = db.Column(db.String(20), nullable=True)  # allow/warn/block

    report = db.relationship(
        'ThreatReport', backref='scan',
        uselist=False, cascade='all, delete-orphan'
    )

    # ── helpers ─────────────────────────────────────────────────────────────

    def to_dict(self):
        return {
            'id':             self.id,
            'url':            self.url,
            'domain':         self.domain,
            'threat_score':   self.threat_score,
            'risk_category':  self.risk_category,
            'scan_type':      self.scan_type,
            'qr_content':     self.qr_content,
            'domain_age_days':self.domain_age_days,
            'ssl_valid':      self.ssl_valid,
            'scan_notes':     self.scan_notes,
            'journal_score':  self.journal_score,
            'hybrid_score':   self.hybrid_score,
            'phishing_prob':  self.phishing_prob,
            'visual_risk':    self.visual_risk,
            'behavior_risk':  self.behavior_risk,
            'domain_risk':    self.domain_risk,
            'final_risk_score': self.final_risk_score,
            'risk_level':     self.risk_level,
            'prevention_action': self.prevention_action,
            'scan_date':      self.scan_date.isoformat() if self.scan_date else None,
        }

    def risk_color(self):
        return {
            'Safe':           '#00ff88',
            'Suspicious':     '#ffaa00',
            'High Risk':      '#ff6600',
            'Critical Threat':'#ff0044',
        }.get(self.risk_category, '#888888')

    def __repr__(self):
        return f'<ScanHistory {self.id} {self.url} {self.risk_category}>'

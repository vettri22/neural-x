"""APIUsage — tracks external API quota consumption."""

from datetime import datetime
from app import db


class APIUsage(db.Model):
    __tablename__ = 'api_usage'

    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(100), nullable=False, index=True)   # virustotal / google_sb etc.
    endpoint = db.Column(db.String(255), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    response_time_ms = db.Column(db.Integer, nullable=True)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text, nullable=True)
    called_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<APIUsage {self.api_name} {self.called_at}>'

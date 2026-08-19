from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Resource(db.Model):
    __tablename__ = 'resources'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    resource_id = db.Column(db.String(120), unique=True, nullable=False)
    resource_name = db.Column(db.String(120), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False) # S3, EC2, IAM, Security Group, RDS
    region = db.Column(db.String(50), default="us-east-1")
    status = db.Column(db.String(50), default="Active")
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)
    security_score = db.Column(db.Integer, default=100)
    config_details = db.Column(db.Text, nullable=True) # JSON payload string of properties

    # Relationship to findings
    findings = db.relationship('Finding', backref='resource_rel', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'resource_name': self.resource_name,
            'resource_type': self.resource_type,
            'region': self.region,
            'status': self.status,
            'last_scanned': self.last_scanned.strftime("%Y-%m-%d %H:%M:%S") if self.last_scanned else None,
            'security_score': self.security_score,
            'findings_count': len(self.findings)
        }


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    finding_id = db.Column(db.String(80), unique=True, nullable=False)
    resource_id = db.Column(db.String(120), db.ForeignKey('resources.resource_id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    recommendation = db.Column(db.Text, nullable=False)
    threat_context = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="Open") # Open, Investigating, Resolved, Ignored
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to alerts
    alerts = db.relationship('Alert', backref='finding_rel', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'resource_id': self.resource_id,
            'resource_name': self.resource_rel.resource_name if self.resource_rel else self.resource_id,
            'resource_type': self.resource_rel.resource_type if self.resource_rel else 'Unknown',
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'recommendation': self.recommendation,
            'threat_context': self.threat_context,
            'status': self.status,
            'detected_at': self.detected_at.strftime("%Y-%m-%d %H:%M:%S") if self.detected_at else None
        }


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    scan_id = db.Column(db.String(80), unique=True, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    resources_scanned = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    security_score = db.Column(db.Integer, default=100)
    scan_mode = db.Column(db.String(20), default="Demo")

    def to_dict(self):
        duration = ""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            duration = f"{delta.total_seconds():.1f}s"
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'started_at': self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else None,
            'completed_at': self.completed_at.strftime("%Y-%m-%d %H:%M:%S") if self.completed_at else None,
            'duration': duration,
            'resources_scanned': self.resources_scanned,
            'findings_count': self.findings_count,
            'security_score': self.security_score,
            'scan_mode': self.scan_mode
        }


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'message': self.message,
            'severity': self.severity,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
            'is_read': self.is_read
        }

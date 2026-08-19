"""
Security Audit Reports Blueprint
Renders formal executive cloud security posture audit reports with print support.
"""

from datetime import datetime
from flask import Blueprint, render_template
from routes.auth import login_required
from models.database_models import Resource, Finding, Scan
from security.risk_engine import calculate_security_score, get_score_category, summarize_findings_by_severity

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
@login_required
def index():
    resources = Resource.query.all()
    findings = Finding.query.all()
    latest_scan = Scan.query.order_by(Scan.started_at.desc()).first()

    severity_counts = summarize_findings_by_severity(findings)
    score = calculate_security_score(findings)
    rating_info = get_score_category(score)

    critical_high_findings = [f for f in findings if f.severity in ['CRITICAL', 'HIGH'] and f.status in ['Open', 'Investigating']]

    report_data = {
        'generated_at': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        'total_resources': len(resources),
        'total_findings': severity_counts['TOTAL'],
        'severity_counts': severity_counts,
        'security_score': score,
        'rating_info': rating_info,
        'latest_scan': latest_scan.to_dict() if latest_scan else None,
        'critical_high_findings': [f.to_dict() for f in critical_high_findings],
        'all_resources': [r.to_dict() for r in resources]
    }

    return render_template('reports.html', report=report_data)

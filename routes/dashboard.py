"""
Dashboard Blueprint
Provides primary SOC security dashboard rendering and analytical statistics API.
"""

from flask import Blueprint, render_template, jsonify, session
from routes.auth import login_required
from models.database_models import Resource, Finding, Scan, Alert
from security.risk_engine import calculate_security_score, get_score_category, summarize_findings_by_severity

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    return render_template('dashboard.html')


@dashboard_bp.route('/api/dashboard-stats')
@login_required
def get_dashboard_stats():
    """Returns real-time aggregated metric values and chart datasets."""
    owner_id = session['user_id']
    resources = Resource.query.filter_by(owner_id=owner_id).all()
    findings = Finding.query.filter_by(owner_id=owner_id).all()
    recent_scans = Scan.query.filter_by(owner_id=owner_id).order_by(Scan.started_at.desc()).limit(5).all()
    recent_alerts = Alert.query.filter_by(owner_id=owner_id).order_by(Alert.created_at.desc()).limit(5).all()

    # Severity distribution
    severity_counts = summarize_findings_by_severity(findings)
    
    # Overall security score
    score = calculate_security_score(findings)
    rating_info = get_score_category(score)

    # Issues grouped by resource type
    issues_by_type = {}
    for f in findings:
        if f.status in ['Open', 'Investigating']:
            res_type = f.resource_rel.resource_type if f.resource_rel else 'Other'
            issues_by_type[res_type] = issues_by_type.get(res_type, 0) + 1

    # Security score trend history from scan logs
    historical_scans = Scan.query.filter_by(owner_id=owner_id).order_by(Scan.started_at.asc()).limit(10).all()
    score_history_labels = [s.started_at.strftime('%m/%d %H:%M') for s in historical_scans] if historical_scans else ['Initial']
    score_history_data = [s.security_score for s in historical_scans] if historical_scans else [score]

    # Latest scan summary
    latest_scan = recent_scans[0].to_dict() if recent_scans else None

    return jsonify({
        'total_resources': len(resources),
        'total_issues': severity_counts['TOTAL'],
        'critical_issues': severity_counts['CRITICAL'],
        'high_issues': severity_counts['HIGH'],
        'medium_issues': severity_counts['MEDIUM'],
        'low_issues': severity_counts['LOW'],
        'security_score': score,
        'rating_info': rating_info,
        'risk_distribution': {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'data': [
                severity_counts['CRITICAL'],
                severity_counts['HIGH'],
                severity_counts['MEDIUM'],
                severity_counts['LOW']
            ]
        },
        'issues_by_resource_type': {
            'labels': list(issues_by_type.keys()),
            'data': list(issues_by_type.values())
        },
        'score_history': {
            'labels': score_history_labels,
            'data': score_history_data
        },
        'recent_scans': [s.to_dict() for s in recent_scans],
        'recent_alerts': [a.to_dict() for a in recent_alerts],
        'latest_scan': latest_scan
    })


@dashboard_bp.route('/api/dashboard/top-problems')
@login_required
def get_top_problems():
    """Returns top open security findings ordered by severity (CRITICAL first)."""
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    findings = Finding.query.filter(
        Finding.owner_id == session['user_id'],
        Finding.status.in_(['Open', 'Investigating'])
    ).all()

    findings.sort(key=lambda f: severity_order.get(f.severity, 9))
    top = findings[:8]

    result = []
    for f in top:
        result.append({
            'id': f.id,
            'finding_id': f.finding_id,
            'title': f.title,
            'description': f.description,
            'severity': f.severity,
            'status': f.status,
            'resource_name': f.resource_rel.resource_name if f.resource_rel else f.resource_id,
            'resource_type': f.resource_rel.resource_type if f.resource_rel else 'Unknown',
            'recommendation': f.recommendation,
            'threat_context': f.threat_context,
            'detected_at': f.detected_at.strftime('%Y-%m-%d %H:%M') if f.detected_at else ''
        })

    return jsonify(result)

"""
Compliance Center Blueprint
Evaluates cloud security posture against regulatory standards (CIS, NIST, PCI-DSS, HIPAA, ISO 27001).
"""

from flask import Blueprint, render_template, jsonify, session
from routes.auth import login_required
from models.database_models import Finding
from security.compliance import evaluate_compliance_posture, COMPLIANCE_FRAMEWORKS

compliance_bp = Blueprint('compliance', __name__)

@compliance_bp.route('/compliance')
@login_required
def index():
    return render_template('compliance.html')


@compliance_bp.route('/api/compliance')
@login_required
def get_compliance_stats():
    findings = Finding.query.filter_by(owner_id=session['user_id']).all()
    evaluations = evaluate_compliance_posture(findings)
    return jsonify({
        'frameworks': evaluations,
        'metadata': COMPLIANCE_FRAMEWORKS
    })

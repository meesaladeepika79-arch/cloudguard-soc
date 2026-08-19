import io
import csv
from flask import Blueprint, render_template, jsonify, request, Response
from routes.auth import login_required
from models.database_models import db, Finding, Resource
from security.risk_engine import calculate_security_score
from security.compliance import get_finding_compliance_mappings
from security.remediation import execute_auto_remediation, generate_remediation_code
from security.webhooks import dispatch_security_alert

findings_bp = Blueprint('findings', __name__)

@findings_bp.route('/findings')
@login_required
def index():
    return render_template('findings.html')


@findings_bp.route('/findings/<int:finding_id>')
@login_required
def view_details(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    compliance_mappings = get_finding_compliance_mappings(finding.finding_id)
    remediation_snippets = generate_remediation_code(finding)
    return render_template(
        'finding_details.html',
        finding=finding,
        compliance_mappings=compliance_mappings,
        remediation_snippets=remediation_snippets
    )


@findings_bp.route('/api/findings')
@login_required
def get_findings():
    severity = request.args.get('severity')
    res_type = request.args.get('resource_type')
    status = request.args.get('status')
    
    query = Finding.query
    if severity and severity != 'ALL':
        query = query.filter_by(severity=severity)
    if status and status != 'ALL':
        query = query.filter_by(status=status)
    if res_type and res_type != 'ALL':
        query = query.join(Resource).filter(Resource.resource_type == res_type)

    findings = query.order_by(Finding.detected_at.desc()).all()
    
    # Enrich with compliance and autofix eligibility
    enriched = []
    for f in findings:
        d = f.to_dict()
        d['compliance'] = get_finding_compliance_mappings(f.finding_id)
        d['can_autofix'] = any(k in f.finding_id for k in ['S3_PUBLIC_ACCESS', 'S3_ENCRYPTION', 'SG_OPEN'])
        enriched.append(d)

    return jsonify(enriched)


@findings_bp.route('/api/findings/<int:finding_id>/autofix', methods=['POST'])
@login_required
def autofix_finding(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    success, message = execute_auto_remediation(finding)
    
    if success:
        finding.status = 'Resolved'
        if finding.resource_rel:
            res_findings = Finding.query.filter_by(resource_id=finding.resource_id).all()
            finding.resource_rel.security_score = calculate_security_score(res_findings)
        
        db.session.commit()
        
        all_findings = Finding.query.all()
        new_overall_score = calculate_security_score(all_findings)
        
        # Dispatch webhook alert for remediation
        dispatch_security_alert(finding, action="AUTOMATICALLY_REMEDIATED")

        return jsonify({
            'success': True,
            'message': message,
            'finding': finding.to_dict(),
            'new_overall_score': new_overall_score
        })
    else:
        return jsonify({
            'success': False,
            'error': message
        }), 500


@findings_bp.route('/api/findings/<int:finding_id>/status', methods=['POST'])
@login_required
def update_status(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    data = request.get_json() or {}
    new_status = data.get('status')

    valid_statuses = ['Open', 'Investigating', 'Resolved', 'Ignored']
    if new_status not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of {valid_statuses}'}), 400

    finding.status = new_status
    
    # Recalculate affected resource security score
    if finding.resource_rel:
        res_findings = Finding.query.filter_by(resource_id=finding.resource_id).all()
        finding.resource_rel.security_score = calculate_security_score(res_findings)

    db.session.commit()

    # Calculate overall updated cloud score
    all_findings = Finding.query.all()
    new_overall_score = calculate_security_score(all_findings)

    return jsonify({
        'message': f'Finding {finding.finding_id} status updated to {new_status}',
        'finding': finding.to_dict(),
        'new_overall_score': new_overall_score
    })


@findings_bp.route('/api/findings/export/csv')
@login_required
def export_findings_csv():
    findings = Finding.query.order_by(Finding.detected_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # CSV Header
    writer.writerow([
        'Finding ID', 'Severity', 'Title', 'Resource ID', 'Resource Name',
        'Resource Type', 'Status', 'Detected At', 'Recommendation',
        'CIS Control', 'NIST Control', 'PCI-DSS Control'
    ])
    
    for f in findings:
        res_name = f.resource_rel.resource_name if f.resource_rel else f.resource_id
        res_type = f.resource_rel.resource_type if f.resource_rel else 'Unknown'
        compliance = {c['framework_key']: c['control'] for c in get_finding_compliance_mappings(f.finding_id)}
        
        writer.writerow([
            f.finding_id,
            f.severity,
            f.title,
            f.resource_id,
            res_name,
            res_type,
            f.status,
            f.detected_at.strftime('%Y-%m-%d %H:%M:%S') if f.detected_at else '',
            f.recommendation,
            compliance.get('CIS_AWS', 'N/A'),
            compliance.get('NIST', 'N/A'),
            compliance.get('PCI_DSS', 'N/A')
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cloudguard_security_findings.csv"}
    )


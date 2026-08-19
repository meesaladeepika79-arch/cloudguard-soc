"""
Security Alerts Blueprint
Displays real-time security alerts generated for Critical & High risk findings.
"""

from flask import Blueprint, render_template, jsonify, request
from routes.auth import login_required
from models.database_models import db, Alert

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
@login_required
def index():
    return render_template('alerts.html')


@alerts_bp.route('/api/alerts')
@login_required
def get_alerts():
    unread_only = request.args.get('unread_only') == 'true'
    query = Alert.query
    if unread_only:
        query = query.filter_by(is_read=False)
        
    alerts = query.order_by(Alert.created_at.desc()).all()
    return jsonify([a.to_dict() for a in alerts])


@alerts_bp.route('/api/alerts/mark-read', methods=['POST'])
@login_required
def mark_read():
    data = request.get_json() or {}
    alert_id = data.get('alert_id')
    mark_all = data.get('mark_all', False)

    if mark_all:
        Alert.query.filter_by(is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'message': 'All alerts marked as read'})
    elif alert_id:
        alert = Alert.query.get_or_404(alert_id)
        alert.is_read = True
        db.session.commit()
        return jsonify({'message': f'Alert {alert_id} marked as read'})
    else:
        return jsonify({'error': 'Specify alert_id or mark_all=true'}), 400


@alerts_bp.route('/api/alerts/count')
@login_required
def unread_count():
    count = Alert.query.filter_by(is_read=False).count()
    return jsonify({'unread_count': count})

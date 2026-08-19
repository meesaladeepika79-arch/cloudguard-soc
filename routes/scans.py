import threading
import time
from flask import Blueprint, render_template, jsonify, request, current_app, session
from routes.auth import login_required
from models.database_models import Scan, Finding
from security.scanner import run_security_scan
from security.webhooks import dispatch_security_alert

scans_bp = Blueprint('scans', __name__)

# Global Background Scheduler State
scheduler_state = {
    'active': False,
    'interval_minutes': 30,
    'last_run': None,
    'thread': None,
    'user_id': None
}

# Secrets stay in server memory only and are scoped by the logged-in user.
aws_connections = {}

def get_aws_connection(user_id):
    return aws_connections.get(user_id, {})

def background_monitor_worker(app, interval_minutes, user_id):
    while scheduler_state['active']:
        try:
            with app.app_context():
                connection = get_aws_connection(user_id)
                run_security_scan(
                    demo_mode=False,
                    owner_id=user_id,
                    region_name=connection.get('region'),
                    access_key_id=connection.get('access_key_id'),
                    secret_access_key=connection.get('secret_access_key'),
                    session_token=connection.get('session_token')
                )
                scheduler_state['last_run'] = time.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            app.logger.warning(f"Background scan iteration error: {e}")
        time.sleep(interval_minutes * 60)


@scans_bp.route('/scans')
@login_required
def index():
    return render_template('scans.html')


@scans_bp.route('/api/scans/run', methods=['POST'])
@login_required
def trigger_scan():
    data = request.get_json() or {}
    use_demo = False
    user_id = session['user_id']
    connection = get_aws_connection(user_id)
    region = (data.get('region') or connection.get('region') or current_app.config.get('AWS_REGION')).strip()
    access_key_id = (data.get('aws_access_key_id') or '').strip()
    secret_access_key = (data.get('aws_secret_access_key') or '').strip()
    session_token = (data.get('aws_session_token') or '').strip() or None

    if access_key_id and secret_access_key:
        aws_connections[user_id] = {
            'access_key_id': access_key_id,
            'secret_access_key': secret_access_key,
            'session_token': session_token,
            'region': region
        }
        connection = aws_connections[user_id]
    else:
        access_key_id = connection.get('access_key_id')
        secret_access_key = connection.get('secret_access_key')
        session_token = connection.get('session_token')

    if not use_demo and (not access_key_id or not secret_access_key):
        return jsonify({
            'error': True,
            'message': 'AWS Access Key ID and Secret Access Key are required for a real AWS scan.'
        }), 400
    
    try:
        result = run_security_scan(
            demo_mode=use_demo,
            region_name=region,
            owner_id=user_id,
            access_key_id=access_key_id or None,
            secret_access_key=secret_access_key or None,
            session_token=session_token
        )
        return jsonify(result)
    except Exception as e:
        current_app.logger.exception(f"Scan execution failed: {e}")
        return jsonify({
            'error': True,
            'message': str(e),
            'mode': 'Error',
            'resources_scanned': 0,
            'security_score': 0
        }), 500


@scans_bp.route('/api/aws-connection', methods=['GET', 'DELETE'])
@login_required
def manage_aws_connection():
    user_id = session['user_id']
    if request.method == 'DELETE':
        aws_connections.pop(user_id, None)
        return jsonify({'connected': False})

    connection = get_aws_connection(user_id)
    return jsonify({
        'connected': bool(connection.get('access_key_id') and connection.get('secret_access_key')),
        'region': connection.get('region')
    })


@scans_bp.route('/api/scans/history')
@login_required
def get_scan_history():
    scans = Scan.query.filter_by(owner_id=session['user_id']).order_by(Scan.started_at.desc()).limit(20).all()
    return jsonify([s.to_dict() for s in scans])


@scans_bp.route('/api/scans/scheduler', methods=['GET', 'POST'])
@login_required
def manage_scheduler():
    global scheduler_state
    if request.method == 'POST':
        data = request.get_json() or {}
        enable = data.get('enable', False)
        interval = int(data.get('interval_minutes', 30))

        scheduler_state['active'] = enable
        scheduler_state['interval_minutes'] = interval
        scheduler_state['user_id'] = session['user_id'] if enable else None

        if enable and (scheduler_state['thread'] is None or not scheduler_state['thread'].is_alive()):
            app_obj = current_app._get_current_object()
            t = threading.Thread(
                target=background_monitor_worker,
                args=(app_obj, interval, session['user_id']),
                daemon=True
            )
            scheduler_state['thread'] = t
            t.start()

    return jsonify({
        'active': scheduler_state['active'],
        'interval_minutes': scheduler_state['interval_minutes'],
        'last_run': scheduler_state['last_run']
    })


@scans_bp.route('/api/webhooks/test', methods=['POST'])
@login_required
def test_webhook():
    data = request.get_json() or {}
    webhook_url = data.get('webhook_url')
    
    # Create sample dummy finding for test
    class DummyFinding:
        finding_id = "FIND-TEST-ALERT"
        title = "CloudGuard SOC Webhook Connectivity Test"
        severity = "HIGH"
        resource_id = "arn:aws:cloudguard:test"
        description = "This is a real-time test notification from your CloudGuard SOC Dashboard."
        recommendation = "Verify webhook channel permissions."
        resource_rel = None

    success, msg = dispatch_security_alert(DummyFinding(), action="TEST_DISPATCH", custom_webhook_url=webhook_url)
    return jsonify({'success': success, 'message': msg})


@scans_bp.route('/api/scans/purge-demo', methods=['POST'])
@login_required
def purge_demo():
    from security.scanner import purge_all_demo_data
    success, msg = purge_all_demo_data()
    return jsonify({'success': success, 'message': msg})



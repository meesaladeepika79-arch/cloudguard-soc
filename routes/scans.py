import threading
import time
from flask import Blueprint, render_template, jsonify, request, current_app
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
    'thread': None
}

def background_monitor_worker(app, interval_minutes):
    while scheduler_state['active']:
        try:
            with app.app_context():
                use_demo = app.config.get('DEMO_MODE', False)
                run_security_scan(demo_mode=use_demo)
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
    use_demo = data.get('demo_mode', current_app.config.get('DEMO_MODE', False))
    region = data.get('region', None)
    
    try:
        result = run_security_scan(demo_mode=use_demo, region_name=region)
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


@scans_bp.route('/api/scans/history')
@login_required
def get_scan_history():
    scans = Scan.query.order_by(Scan.started_at.desc()).limit(20).all()
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

        if enable and (scheduler_state['thread'] is None or not scheduler_state['thread'].is_alive()):
            app_obj = current_app._get_current_object()
            t = threading.Thread(target=background_monitor_worker, args=(app_obj, interval), daemon=True)
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



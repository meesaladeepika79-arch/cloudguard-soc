import os
from flask import Flask
from config import Config
from models.database_models import db, User, Resource, Finding, Scan
from security.scanner import run_security_scan

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.resources import resources_bp
    from routes.findings import findings_bp
    from routes.scans import scans_bp
    from routes.alerts import alerts_bp
    from routes.reports import reports_bp
    from routes.compliance import compliance_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(compliance_bp)

    # Initialize Database and Seed Demo Data
    with app.app_context():
        try:
            os.makedirs(app.instance_path, exist_ok=True)
        except OSError:
            pass

        db.create_all()

        # Seed Default Admin User if missing
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("[+] Seeded default admin user: admin / admin123")

        # Initial Scan Run if DB has no scan history and DEMO_MODE is True
        if app.config.get('DEMO_MODE', False):
            scan_count = Scan.query.count()
            if scan_count == 0:
                print("[+] Seeding initial demo scan and mock cloud resources...")
                run_security_scan(demo_mode=True)
                print("[+] Demo cloud environment initialized successfully.")

    return app


app = create_app()

if __name__ == '__main__':
    print("=================================================================")
    print("  Cloud Security Monitoring Dashboard running on http://127.0.0.1:5000")
    print(" Default Login: admin / admin123")
    print("=================================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)

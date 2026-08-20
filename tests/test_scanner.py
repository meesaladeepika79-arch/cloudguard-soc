import pathlib

import pytest
from security.rules import check_s3_rules, check_ec2_rules, check_iam_rules, check_sg_rules, check_rds_rules
from security.risk_engine import calculate_security_score, get_score_category
from security.aws_scanner import validate_aws_key_format
from models.database_models import User

def test_s3_public_access_rule():
    insecure_s3 = {
        'name': 'vulnerable-bucket',
        'public_access_enabled': True,
        'block_public_access': False,
        'encryption_enabled': False
    }
    findings = check_s3_rules(insecure_s3)
    severities = [f['severity'] for f in findings]
    assert 'HIGH' in severities
    assert 'MEDIUM' in severities
    assert len(findings) >= 2


def test_iam_administrator_access_rule():
    admin_iam = {
        'name': 'dangerous-admin',
        'has_admin_privileges': True,
        'mfa_enabled': False,
        'key_age_days': 100
    }
    findings = check_iam_rules(admin_iam)
    severities = [f['severity'] for f in findings]
    assert 'CRITICAL' in severities
    assert len(findings) >= 2


def test_security_group_open_ports():
    sg_config = {
        'name': 'open-all-sg',
        'open_ingress_rules': [
            {'port': 22, 'cidr': '0.0.0.0/0'},
            {'port': 3306, 'cidr': '0.0.0.0/0'}
        ]
    }
    findings = check_sg_rules(sg_config)
    assert any(f['rule_id'] == 'SG_OPEN_SSH' for f in findings)
    assert any(f['rule_id'] == 'SG_OPEN_DATABASE' for f in findings)


def test_risk_score_calculation():
    findings = [
        {'severity': 'CRITICAL', 'status': 'Open'}, # -20
        {'severity': 'HIGH', 'status': 'Open'},     # -12
        {'severity': 'MEDIUM', 'status': 'Open'}    # -6
    ]
    # Score = 100 - (20 + 12 + 6) = 62
    score = calculate_security_score(findings)
    assert score == 62
    
    category = get_score_category(score)
    assert category['rating'] == 'NEEDS IMPROVEMENT'


def test_resolved_findings_do_not_deduct():
    findings = [
        {'severity': 'CRITICAL', 'status': 'Resolved'},
        {'severity': 'HIGH', 'status': 'Resolved'}
    ]
    # Score should be 100 because all findings are resolved
    score = calculate_security_score(findings)
    assert score == 100
    category = get_score_category(score)
    assert category['rating'] == 'EXCELLENT'


def test_user_password_hashing():
    u = User(username='testadmin')
    u.set_password('securepassword123')
    assert u.password_hash != 'securepassword123'
    assert u.check_password('securepassword123') is True
    assert u.check_password('wrongpassword') is False


def test_validate_aws_key_format_enforces_strong_credentials():
    ok, message = validate_aws_key_format(
        'AKIAIOSFODNN7EXAMPLE',
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    )
    assert ok is True
    assert message is None

    invalid, msg = validate_aws_key_format('bad-key', 'short-secret')
    assert invalid is False
    assert 'invalid' in msg.lower()


def test_dashboard_password_fields_do_not_trigger_password_manager_suggestions():
    dashboard_template = pathlib.Path(__file__).resolve().parents[1] / 'templates' / 'dashboard.html'
    content = dashboard_template.read_text(encoding='utf-8')
    assert 'autocomplete="new-password"' not in content
    assert 'autocomplete="off"' in content

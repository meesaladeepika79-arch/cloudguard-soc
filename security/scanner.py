"""
Scanner Engine Coordinator
Manages mock cloud resource generation, AWS discovery integration, rule execution,
score calculation, and database synchronization.
"""

import json
import logging
import uuid
from datetime import datetime
from models.database_models import db, Resource, Finding, Scan, Alert
from config import Config
from security.rules import (
    check_s3_rules, check_ec2_rules, check_iam_rules,
    check_sg_rules, check_rds_rules
)
from security.risk_engine import calculate_security_score, summarize_findings_by_severity
from security.aws_scanner import discover_aws_resources

logger = logging.getLogger(__name__)

def get_demo_resources():
    """Generates realistic mock cloud resources for demonstration mode."""
    return [
        {
            'resource_id': 'arn:aws:s3:::production-data-bucket',
            'resource_name': 'production-data-bucket',
            'resource_type': 'S3',
            'region': 'us-east-1',
            'status': 'Active',
            'config': {
                'name': 'production-data-bucket',
                'public_access_enabled': True,
                'block_public_access': False,
                'encryption_enabled': False,
                'versioning_enabled': False
            }
        },
        {
            'resource_id': 'arn:aws:s3:::finance-backups-2026',
            'resource_name': 'finance-backups-2026',
            'resource_type': 'S3',
            'region': 'us-west-2',
            'status': 'Active',
            'config': {
                'name': 'finance-backups-2026',
                'public_access_enabled': False,
                'block_public_access': True,
                'encryption_enabled': True,
                'versioning_enabled': True
            }
        },
        {
            'resource_id': 'i-09f8723b12345678a',
            'resource_name': 'web-server-01',
            'resource_type': 'EC2',
            'region': 'us-east-1',
            'status': 'Running',
            'config': {
                'name': 'web-server-01',
                'public_ip_assigned': True,
                'public_ip': '54.210.12.88',
                'environment': 'production',
                'iam_instance_profile': False,
                'detailed_monitoring': False
            }
        },
        {
            'resource_id': 'i-01a23b45c67890def',
            'resource_name': 'app-worker-node',
            'resource_type': 'EC2',
            'region': 'us-east-1',
            'status': 'Running',
            'config': {
                'name': 'app-worker-node',
                'public_ip_assigned': False,
                'environment': 'production',
                'iam_instance_profile': True,
                'detailed_monitoring': True
            }
        },
        {
            'resource_id': 'arn:aws:iam::123456789012:user/admin-user',
            'resource_name': 'admin-user',
            'resource_type': 'IAM',
            'region': 'global',
            'status': 'Active',
            'config': {
                'name': 'admin-user',
                'has_admin_privileges': True,
                'mfa_enabled': False,
                'key_age_days': 120
            }
        },
        {
            'resource_id': 'arn:aws:iam::123456789012:user/sec-auditor-read',
            'resource_name': 'sec-auditor-read',
            'resource_type': 'IAM',
            'region': 'global',
            'status': 'Active',
            'config': {
                'name': 'sec-auditor-read',
                'has_admin_privileges': False,
                'mfa_enabled': True,
                'key_age_days': 30
            }
        },
        {
            'resource_id': 'sg-0a1b2c3d4e5f67890',
            'resource_name': 'sg-web-public',
            'resource_type': 'Security Group',
            'region': 'us-east-1',
            'status': 'Active',
            'config': {
                'name': 'sg-web-public',
                'open_ingress_rules': [
                    {'port': 22, 'cidr': '0.0.0.0/0'},
                    {'port': 3306, 'cidr': '0.0.0.0/0'}
                ]
            }
        },
        {
            'resource_id': 'sg-9f8e7d6c5b4a3210',
            'resource_name': 'sg-internal-db',
            'resource_type': 'Security Group',
            'region': 'us-east-1',
            'status': 'Active',
            'config': {
                'name': 'sg-internal-db',
                'open_ingress_rules': [
                    {'port': 5432, 'cidr': '10.0.1.0/24'}
                ]
            }
        },
        {
            'resource_id': 'arn:aws:rds:us-east-1:123456789012:db:prod-mysql-db',
            'resource_name': 'prod-mysql-db',
            'resource_type': 'RDS',
            'region': 'us-east-1',
            'status': 'Available',
            'config': {
                'name': 'prod-mysql-db',
                'publicly_accessible': True,
                'storage_encrypted': False,
                'multi_az': False
            }
        },
        {
            'resource_id': 'arn:aws:rds:us-east-1:123456789012:db:analytics-postgres',
            'resource_name': 'analytics-postgres',
            'resource_type': 'RDS',
            'region': 'us-east-1',
            'status': 'Available',
            'config': {
                'name': 'analytics-postgres',
                'publicly_accessible': False,
                'storage_encrypted': True,
                'multi_az': True
            }
        }
    ]


DEMO_MOCK_RESOURCE_IDS = [
    'arn:aws:s3:::production-data-bucket',
    'arn:aws:s3:::finance-backups-2026',
    'i-09f8723b12345678a',
    'i-01a23b45c67890def',
    'arn:aws:iam::123456789012:user/admin-user',
    'arn:aws:iam::123456789012:user/sec-auditor-read',
    'sg-0a1b2c3d4e5f67890',
    'sg-9f8e7d6c5b4a3210',
    'arn:aws:rds:us-east-1:123456789012:db:prod-mysql-db',
    'arn:aws:rds:us-east-1:123456789012:db:analytics-postgres'
]

def purge_all_demo_data():
    """Completely wipes all mock/simulated demo resources, findings, alerts, and demo scans."""
    try:
        for mock_id in DEMO_MOCK_RESOURCE_IDS:
            findings = Finding.query.filter_by(resource_id=mock_id).all()
            for f in findings:
                Alert.query.filter_by(finding_id=f.id).delete()
                db.session.delete(f)
            Resource.query.filter_by(resource_id=mock_id).delete()

        # Delete any demo scan entries from history
        Scan.query.filter(Scan.scan_mode.like('%Demo%')).delete()
        db.session.commit()
        logger.info("Purged all simulated demo resources and findings successfully.")
        return True, "Demo resources and findings removed."
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Failed to purge demo data: {e}")
        return False, str(e)


def run_security_scan(demo_mode=True, region_name=None):
    """
    Executes an end-to-end security scan.
    1. Collects raw resources (Mock generator or AWS Boto3 across regions).
    2. Runs security rules against each resource.
    3. Calculates security scores.
    4. Syncs database records (Resources, Findings, Scans, Alerts).
    """
    started_at = datetime.utcnow()
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    scan_mode_str = "Demo" if demo_mode else "AWS"
    target_region = region_name or Config.AWS_REGION or 'us-east-1'

    # Step 1: Retrieve Cloud Resources
    error_msg = None
    if demo_mode:
        raw_resources = get_demo_resources()
    else:
        # Wipe out any residual demo/mock resources so only real AWS assets show
        purge_all_demo_data()

        raw_resources, error_msg = discover_aws_resources(region_name=target_region)
        if error_msg:
            # Do NOT silently fallback to mock demo resources when user requested real AWS
            raw_resources = []
            scan_mode_str = "AWS (No Resources / Check Credentials)"

    scanned_resources_count = len(raw_resources)
    all_findings_objects = []

    # Step 2 & 3: Upsert Resources and Evaluate Rules
    for item in raw_resources:
        res_id = item['resource_id']
        res_name = item['resource_name']
        res_type = item['resource_type']
        region = item['region']
        status = item['status']
        config = item['config']

        # Find or create DB Resource entry
        resource_db = Resource.query.filter_by(resource_id=res_id).first()
        if not resource_db:
            resource_db = Resource(
                resource_id=res_id,
                resource_name=res_name,
                resource_type=res_type,
                region=region,
                status=status,
                config_details=json.dumps(config)
            )
            db.session.add(resource_db)
        else:
            resource_db.resource_name = res_name
            resource_db.status = status
            resource_db.config_details = json.dumps(config)
            resource_db.last_scanned = started_at
        
        db.session.flush()

        # Evaluate rules based on resource type
        detected_rule_findings = []
        if res_type == 'S3':
            detected_rule_findings = check_s3_rules(config)
        elif res_type == 'EC2':
            detected_rule_findings = check_ec2_rules(config)
        elif res_type == 'IAM':
            detected_rule_findings = check_iam_rules(config)
        elif res_type == 'Security Group':
            detected_rule_findings = check_sg_rules(config)
        elif res_type == 'RDS':
            detected_rule_findings = check_rds_rules(config)

        # Process detected findings for this resource
        resource_findings_objs = []
        triggered_rule_ids = set()

        for df in detected_rule_findings:
            f_rule_id = df['rule_id']
            triggered_rule_ids.add(f_rule_id)
            finding_unique_id = f"FIND-{res_name[:6].upper()}-{f_rule_id}"

            # Check existing finding in DB
            existing_finding = Finding.query.filter_by(finding_id=finding_unique_id).first()
            if not existing_finding:
                existing_finding = Finding(
                    finding_id=finding_unique_id,
                    resource_id=res_id,
                    title=df['title'],
                    description=df['description'],
                    severity=df['severity'],
                    recommendation=df['recommendation'],
                    threat_context=df['threat_context'],
                    status='Open',
                    detected_at=started_at
                )
                db.session.add(existing_finding)
                db.session.flush()

                # Generate alert for CRITICAL or HIGH findings
                if df['severity'] in ['CRITICAL', 'HIGH']:
                    alert = Alert(
                        finding_id=existing_finding.id,
                        message=f"[{df['severity']}] {df['title']} detected on {res_name}",
                        severity=df['severity'],
                        created_at=started_at,
                        is_read=False
                    )
                    db.session.add(alert)
            else:
                # Re-open finding if it was previously ignored/resolved but rule fires again
                if existing_finding.status in ('Resolved', 'Ignored'):
                    existing_finding.status = 'Open'

            resource_findings_objs.append(existing_finding)
            all_findings_objects.append(existing_finding)

        # ── AUTO-RESOLVE ──────────────────────────────────────────────────────
        # Any existing Open/Investigating finding for this resource whose rule
        # was NOT triggered in this scan means the misconfiguration is now fixed
        # in AWS → automatically mark it Resolved.
        existing_resource_findings = Finding.query.filter_by(resource_id=res_id).all()
        triggered_finding_ids = {
            f"FIND-{res_name[:6].upper()}-{rule_id}" for rule_id in triggered_rule_ids
        }
        for ef in existing_resource_findings:
            if ef.finding_id not in triggered_finding_ids:
                if ef.status in ('Open', 'Investigating'):
                    logger.info(
                        f"Auto-resolving {ef.finding_id} — no longer triggered "
                        f"on {res_name} (misconfiguration fixed in AWS)"
                    )
                    ef.status = 'Resolved'
        # ─────────────────────────────────────────────────────────────────────

        # Calculate individual resource score
        res_score = calculate_security_score(resource_findings_objs)
        resource_db.security_score = res_score

    db.session.commit()

    # Query all current active findings from database for complete system score calculation
    active_db_findings = Finding.query.all()
    overall_score = calculate_security_score(active_db_findings)

    # Record Scan History entry
    completed_at = datetime.utcnow()
    scan_record = Scan(
        scan_id=scan_id,
        started_at=started_at,
        completed_at=completed_at,
        resources_scanned=scanned_resources_count,
        findings_count=len(active_db_findings),
        security_score=overall_score,
        scan_mode=scan_mode_str
    )
    db.session.add(scan_record)
    db.session.commit()

    return {
        'scan_id': scan_id,
        'mode': scan_mode_str,
        'resources_scanned': scanned_resources_count,
        'findings_count': len(active_db_findings),
        'security_score': overall_score,
        'warning': error_msg
    }

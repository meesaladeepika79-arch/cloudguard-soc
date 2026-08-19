"""
Regulatory Compliance Framework Mapping Engine
Maps detected security findings to industry cybersecurity standards:
- CIS AWS Foundations Benchmark v1.4.0
- NIST SP 800-53 Rev 5
- PCI-DSS v4.0
- HIPAA Security Rule (45 CFR Part 160 and Part 164)
- ISO/IEC 27001:2022
"""

COMPLIANCE_FRAMEWORKS = {
    'CIS_AWS': {
        'name': 'CIS AWS Foundations Benchmark',
        'version': 'v1.4.0',
        'badge_color': '#38bdf8',
        'description': 'Consensus-based best practices for securing Amazon Web Services accounts.'
    },
    'NIST': {
        'name': 'NIST SP 800-53',
        'version': 'Rev 5',
        'badge_color': '#a855f7',
        'description': 'Security and Privacy Controls for Information Systems and Organizations.'
    },
    'PCI_DSS': {
        'name': 'PCI-DSS',
        'version': 'v4.0',
        'badge_color': '#f59e0b',
        'description': 'Payment Card Industry Data Security Standard for protecting cardholder data.'
    },
    'HIPAA': {
        'name': 'HIPAA Security Rule',
        'version': '45 CFR § 164',
        'badge_color': '#10b981',
        'description': 'National standards to protect individuals electronic personal health information.'
    },
    'ISO_27001': {
        'name': 'ISO/IEC 27001',
        'version': '2022',
        'badge_color': '#ec4899',
        'description': 'International standard for managing information security risks.'
    }
}

# Mapping of Rule IDs to Compliance Framework Controls
RULE_COMPLIANCE_MAP = {
    'S3_PUBLIC_ACCESS': {
        'CIS_AWS': {'control': '2.1.5', 'title': 'Ensure S3 Bucket Public Access is Blocked'},
        'NIST': {'control': 'AC-3', 'title': 'Access Enforcement & Public Sharing Restrictions'},
        'PCI_DSS': {'control': 'Req 1.3', 'title': 'Prohibit direct public access to internal cardholder data'},
        'HIPAA': {'control': '§ 164.312(a)(1)', 'title': 'Access Control to ePHI Storage'},
        'ISO_27001': {'control': 'A.8.20', 'title': 'Network & Cloud Storage Security'}
    },
    'S3_ENCRYPTION_DISABLED': {
        'CIS_AWS': {'control': '2.1.1', 'title': 'Ensure S3 Buckets are Encrypted at Rest with SSE'},
        'NIST': {'control': 'SC-28', 'title': 'Protection of Information at Rest'},
        'PCI_DSS': {'control': 'Req 3.4', 'title': 'Render PAN unreadable anywhere it is stored'},
        'HIPAA': {'control': '§ 164.312(a)(2)(iv)', 'title': 'Encryption and Decryption of ePHI'},
        'ISO_27001': {'control': 'A.8.24', 'title': 'Use of Cryptography'}
    },
    'EC2_PUBLIC_EXPOSURE': {
        'CIS_AWS': {'control': '5.2', 'title': 'Ensure Production EC2 Instances are in Private Subnets'},
        'NIST': {'control': 'SC-7', 'title': 'Boundary Protection & Network Segmentation'},
        'PCI_DSS': {'control': 'Req 1.2', 'title': 'Restrict inbound/outbound traffic to necessary services'},
        'HIPAA': {'control': '§ 164.312(e)(1)', 'title': 'Transmission Security & Boundary Controls'},
        'ISO_27001': {'control': 'A.8.20', 'title': 'Network Controls and Segregation'}
    },
    'IAM_EXCESSIVE_PERMISSIONS': {
        'CIS_AWS': {'control': '1.16', 'title': 'Ensure IAM policies are not granting full *:* AdministratorAccess'},
        'NIST': {'control': 'AC-6', 'title': 'Least Privilege Access Management'},
        'PCI_DSS': {'control': 'Req 7.2', 'title': 'Establish an access control system based on least privilege'},
        'HIPAA': {'control': '§ 164.312(a)(1)', 'title': 'Unique User Identification & Role-Based Access'},
        'ISO_27001': {'control': 'A.9.2', 'title': 'User Access Provisioning & Privilege Management'}
    },
    'IAM_MFA_DISABLED': {
        'CIS_AWS': {'control': '1.5', 'title': 'Ensure MFA is enabled for all IAM users with console access'},
        'NIST': {'control': 'IA-2(1)', 'title': 'Multi-Factor Authentication for Privileged Accounts'},
        'PCI_DSS': {'control': 'Req 8.3', 'title': 'Multi-Factor Authentication for all administrative access'},
        'HIPAA': {'control': '§ 164.312(d)', 'title': 'Person or Entity Authentication'},
        'ISO_27001': {'control': 'A.9.4', 'title': 'User Authentication & Multi-Factor Access'}
    },
    'SG_OPEN_SSH': {
        'CIS_AWS': {'control': '4.1', 'title': 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to port 22'},
        'NIST': {'control': 'AC-17', 'title': 'Remote Access Management'},
        'PCI_DSS': {'control': 'Req 2.2', 'title': 'Secure system components & disable insecure ports'},
        'HIPAA': {'control': '§ 164.312(e)(1)', 'title': 'Secure Transmission & Port Restrictions'},
        'ISO_27001': {'control': 'A.8.20', 'title': 'Network Security Controls'}
    },
    'SG_OPEN_DATABASE': {
        'CIS_AWS': {'control': '4.2', 'title': 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to Database ports'},
        'NIST': {'control': 'SC-7(5)', 'title': 'Deny by default / Isolate database tier'},
        'PCI_DSS': {'control': 'Req 1.3.1', 'title': 'Prohibit direct public inbound traffic to database systems'},
        'HIPAA': {'control': '§ 164.312(c)(1)', 'title': 'Data Integrity & Isolation of Health Databases'},
        'ISO_27001': {'control': 'A.8.20', 'title': 'Network Controls - Database Segregation'}
    },
    'RDS_PUBLIC_ACCESSIBLE': {
        'CIS_AWS': {'control': '2.3.1', 'title': 'Ensure RDS database instances are not publicly accessible'},
        'NIST': {'control': 'SC-7', 'title': 'Boundary Protection & Database Isolation'},
        'PCI_DSS': {'control': 'Req 1.3', 'title': 'Prohibit public access to database servers'},
        'HIPAA': {'control': '§ 164.312(a)(1)', 'title': 'Access Control - Private Subnet Hosting'},
        'ISO_27001': {'control': 'A.8.20', 'title': 'Cloud Database Boundary Controls'}
    },
    'RDS_ENCRYPTION_DISABLED': {
        'CIS_AWS': {'control': '2.3.2', 'title': 'Ensure RDS storage is encrypted at rest using KMS'},
        'NIST': {'control': 'SC-28(1)', 'title': 'Cryptographic Protection of Database Storage at Rest'},
        'PCI_DSS': {'control': 'Req 3.4', 'title': 'Protect stored cardholder data with strong cryptography'},
        'HIPAA': {'control': '§ 164.312(a)(2)(iv)', 'title': 'Encryption of Electronic Protected Health Information'},
        'ISO_27001': {'control': 'A.8.24', 'title': 'Cryptographic Storage Controls'}
    }
}


def get_finding_compliance_mappings(rule_id_or_finding_id):
    """Returns a list of compliance mappings for a given rule or finding ID."""
    rule_id = rule_id_or_finding_id
    if '-' in rule_id_or_finding_id:
        parts = rule_id_or_finding_id.split('-', 2)
        if len(parts) == 3:
            rule_id = parts[2]
    
    mapping = RULE_COMPLIANCE_MAP.get(rule_id, {})
    results = []
    for fw_key, ctrl_info in mapping.items():
        fw_meta = COMPLIANCE_FRAMEWORKS.get(fw_key, {})
        results.append({
            'framework_key': fw_key,
            'framework_name': fw_meta.get('name', fw_key),
            'version': fw_meta.get('version', ''),
            'badge_color': fw_meta.get('badge_color', '#38bdf8'),
            'control': ctrl_info.get('control', ''),
            'title': ctrl_info.get('title', '')
        })
    return results


def evaluate_compliance_posture(findings):
    """
    Evaluates global compliance scores across all 5 frameworks based on active findings.
    Returns framework summaries with percentage scores and control-by-control status.
    """
    open_findings = [f for f in findings if getattr(f, 'status', 'Open') in ('Open', 'Investigating')]
    
    # Extract triggered rule IDs
    failed_rule_ids = set()
    for f in open_findings:
        f_id = getattr(f, 'finding_id', '')
        parts = f_id.split('-', 2)
        if len(parts) == 3:
            failed_rule_ids.add(parts[2])
        else:
            failed_rule_ids.add(f_id)

    framework_evaluations = {}

    for fw_key, fw_meta in COMPLIANCE_FRAMEWORKS.items():
        total_controls = 0
        passed_controls = 0
        control_list = []

        for rule_id, rule_mappings in RULE_COMPLIANCE_MAP.items():
            if fw_key in rule_mappings:
                ctrl_info = rule_mappings[fw_key]
                total_controls += 1
                is_failed = rule_id in failed_rule_ids

                # Find affected resources if failed
                affected_resources = []
                if is_failed:
                    for f in open_findings:
                        parts = getattr(f, 'finding_id', '').split('-', 2)
                        r_id = parts[2] if len(parts) == 3 else getattr(f, 'finding_id', '')
                        if r_id == rule_id:
                            res_name = f.resource_rel.resource_name if getattr(f, 'resource_rel', None) else f.resource_id
                            affected_resources.append(res_name)

                if not is_failed:
                    passed_controls += 1

                control_list.append({
                    'control': ctrl_info['control'],
                    'title': ctrl_info['title'],
                    'rule_id': rule_id,
                    'status': 'FAIL' if is_failed else 'PASS',
                    'affected_count': len(affected_resources),
                    'affected_resources': affected_resources[:3]
                })

        score_pct = int((passed_controls / total_controls) * 100) if total_controls > 0 else 100

        framework_evaluations[fw_key] = {
            'key': fw_key,
            'name': fw_meta['name'],
            'version': fw_meta['version'],
            'description': fw_meta['description'],
            'badge_color': fw_meta['badge_color'],
            'score_pct': score_pct,
            'passed_controls': passed_controls,
            'failed_controls': total_controls - passed_controls,
            'total_controls': total_controls,
            'controls': control_list
        }

    return framework_evaluations

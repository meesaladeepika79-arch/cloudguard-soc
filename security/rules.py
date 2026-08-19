"""
Security Rules Module
Defines misconfiguration detection logic for S3, EC2, IAM, Security Groups, and RDS.
"""

def check_s3_rules(resource_config):
    """Inspects S3 Bucket configuration for security vulnerabilities."""
    findings = []
    
    # Check 1: S3 Public Access
    if resource_config.get('public_access_enabled', False) or not resource_config.get('block_public_access', True):
        findings.append({
            'rule_id': 'S3_PUBLIC_ACCESS',
            'title': 'S3 Bucket Public Access Enabled',
            'severity': 'HIGH',
            'description': f"The storage bucket '{resource_config.get('name')}' is configured to allow public read/write access without access control restrictions.",
            'threat_context': 'Exposing S3 buckets publicly can lead to sensitive data leakage, compliance violations, and data tampering by unauthorized internet actors.',
            'recommendation': 'Enable "Block all public access" at the bucket and account level, and enforce strict IAM/Bucket policies.'
        })
        
    # Check 2: S3 Default Encryption
    if not resource_config.get('encryption_enabled', True):
        findings.append({
            'rule_id': 'S3_ENCRYPTION_DISABLED',
            'title': 'S3 Bucket Default Encryption Disabled',
            'severity': 'MEDIUM',
            'description': f"Server-Side Encryption (SSE) is disabled on bucket '{resource_config.get('name')}'.",
            'threat_context': 'Unencrypted data at rest is vulnerable if physical media or storage snapshots are compromised.',
            'recommendation': 'Enable SSE-S3 or AWS KMS default server-side encryption for all objects in the bucket.'
        })

    # Check 3: S3 Versioning
    if not resource_config.get('versioning_enabled', True):
        findings.append({
            'rule_id': 'S3_VERSIONING_DISABLED',
            'title': 'S3 Bucket Versioning Disabled',
            'severity': 'LOW',
            'description': f"Bucket versioning is turned off for '{resource_config.get('name')}'.",
            'threat_context': 'Without versioning, accidental deletions or malicious ransomware overwrites cannot be easily recovered.',
            'recommendation': 'Enable bucket versioning to keep past object iterations safe.'
        })

    return findings


def check_ec2_rules(resource_config):
    """Inspects EC2 Instance configuration for security misconfigurations."""
    findings = []

    # Check 1: EC2 Publicly Exposed
    if resource_config.get('public_ip_assigned', False) and resource_config.get('environment') == 'production':
        findings.append({
            'rule_id': 'EC2_PUBLIC_EXPOSURE',
            'title': 'Production EC2 Instance Directly Exposed to Internet',
            'severity': 'HIGH',
            'description': f"Instance '{resource_config.get('name')}' has a public IP assigned ({resource_config.get('public_ip', 'Dynamic')}) in a production network.",
            'threat_context': 'Direct internet access increases attack surface, making instances targets for brute force, port scans, and unpatched zero-day exploits.',
            'recommendation': 'Move instance to a private subnet behind an Application Load Balancer (ALB) or NAT Gateway.'
        })

    # Check 2: Missing IAM Role
    if not resource_config.get('iam_instance_profile'):
        findings.append({
            'rule_id': 'EC2_NO_IAM_ROLE',
            'title': 'EC2 Instance Lacks IAM Instance Profile',
            'severity': 'MEDIUM',
            'description': f"Instance '{resource_config.get('name')}' does not have an IAM role attached.",
            'threat_context': 'Developers may hardcode static AWS credentials inside instance applications, leading to credential theft.',
            'recommendation': 'Attach an IAM role with least-privilege policies to the instance profile instead of using access keys.'
        })

    # Check 3: Detailed Monitoring Disabled
    if not resource_config.get('detailed_monitoring', False):
        findings.append({
            'rule_id': 'EC2_MONITORING_DISABLED',
            'title': 'EC2 Detailed CloudWatch Monitoring Disabled',
            'severity': 'LOW',
            'description': f"Instance '{resource_config.get('name')}' is using basic 5-minute telemetry monitoring.",
            'threat_context': 'Slower metric intervals reduce operational visibility during fast-moving cyber attacks or resource exhaustion.',
            'recommendation': 'Enable EC2 detailed monitoring for 1-minute metric updates.'
        })

    return findings


def check_iam_rules(resource_config):
    """Inspects IAM Users and Policies for access control risks."""
    findings = []

    # Check 1: Excessive Administrator Privileges
    if resource_config.get('has_admin_privileges', False):
        findings.append({
            'rule_id': 'IAM_EXCESSIVE_PERMISSIONS',
            'title': 'IAM User Has Excessive Administrator Access',
            'severity': 'CRITICAL',
            'description': f"IAM User '{resource_config.get('name')}' is directly attached full 'AdministratorAccess' (*:*) policy.",
            'threat_context': 'If credentials for this account are compromised, attackers gain full administrative control over the entire cloud infrastructure.',
            'recommendation': 'Enforce Principle of Least Privilege (PoLP). Remove AdministratorAccess and assign granular role-based access policies.'
        })

    # Check 2: MFA Disabled
    if not resource_config.get('mfa_enabled', False):
        findings.append({
            'rule_id': 'IAM_MFA_DISABLED',
            'title': 'Multi-Factor Authentication (MFA) Disabled for IAM User',
            'severity': 'CRITICAL',
            'description': f"IAM Identity '{resource_config.get('name')}' does not have hardware or virtual MFA activated.",
            'threat_context': 'Accounts protected only by passwords are highly vulnerable to phishing, credential stuffing, and dictionary attacks.',
            'recommendation': 'Enforce mandatory MFA for all console users and administrative identities.'
        })

    # Check 3: Unused Access Keys (> 90 days)
    if resource_config.get('key_age_days', 0) > 90:
        findings.append({
            'rule_id': 'IAM_STALE_ACCESS_KEYS',
            'title': 'IAM Access Keys Not Rotated For Over 90 Days',
            'severity': 'MEDIUM',
            'description': f"Access key for user '{resource_config.get('name')}' is {resource_config.get('key_age_days')} days old.",
            'threat_context': 'Long-lived credentials increase the risk of accidental exposure in git commits or log files.',
            'recommendation': 'Rotate access keys every 90 days or migrate to temporary IAM roles/AWS IAM Identity Center.'
        })

    return findings


def check_sg_rules(resource_config):
    """Inspects Security Group ingress rules for dangerous open ports."""
    findings = []
    open_rules = resource_config.get('open_ingress_rules', [])

    for rule in open_rules:
        port = rule.get('port')
        cidr = rule.get('cidr')

        if cidr == '0.0.0.0/0':
            if port in [22, '22']:
                findings.append({
                    'rule_id': 'SG_OPEN_SSH',
                    'title': 'Security Group Ingress Allows Unrestricted SSH (Port 22)',
                    'severity': 'HIGH',
                    'description': f"Security Group '{resource_config.get('name')}' allows inbound SSH connection from ANY IP (0.0.0.0/0).",
                    'threat_context': 'Exposing SSH globally allows brute-force attacks and automated SSH scanners to continuously target server logins.',
                    'recommendation': 'Restrict SSH access to trusted corporate IP ranges or use AWS Systems Manager (SSM) Session Manager.'
                })
            elif port in [3389, '3389']:
                findings.append({
                    'rule_id': 'SG_OPEN_RDP',
                    'title': 'Security Group Ingress Allows Unrestricted RDP (Port 3389)',
                    'severity': 'HIGH',
                    'description': f"Security Group '{resource_config.get('name')}' allows inbound Windows RDP connection from ANY IP (0.0.0.0/0).",
                    'threat_context': 'Open RDP is a top vector for ransomware installation and remote desktop exploitation.',
                    'recommendation': 'Restrict RDP ingress to specific VPN IP gateways.'
                })
            elif port in [3306, 5432, 1433, 27017, '3306', '5432', '1433', '27017']:
                findings.append({
                    'rule_id': 'SG_OPEN_DATABASE',
                    'title': 'Database Port Open to World (0.0.0.0/0)',
                    'severity': 'CRITICAL',
                    'description': f"Security Group '{resource_config.get('name')}' permits public connections on DB port {port}.",
                    'threat_context': 'Direct database exposure permits credential brute-forcing, SQL injection attempts, and data exfiltration.',
                    'recommendation': 'Remove 0.0.0.0/0 ingress. Only allow database access from application security group IDs.'
                })
            elif port in ['ALL', '-1', '0-65535']:
                findings.append({
                    'rule_id': 'SG_ALL_TRAFFIC_OPEN',
                    'title': 'Security Group Allows ALL Inbound Traffic',
                    'severity': 'CRITICAL',
                    'description': f"Security Group '{resource_config.get('name')}' has a wildcard rule allowing all protocol traffic from 0.0.0.0/0.",
                    'threat_context': 'Completely bypasses network firewall boundaries.',
                    'recommendation': 'Delete all-traffic rules and specify explicit port numbers and source CIDRs.'
                })

    return findings


def check_rds_rules(resource_config):
    """Inspects RDS Database Instance configurations."""
    findings = []

    # Check 1: Publicly Accessible DB
    if resource_config.get('publicly_accessible', False):
        findings.append({
            'rule_id': 'RDS_PUBLIC_ACCESSIBLE',
            'title': 'RDS Database Instance Set To Publicly Accessible',
            'severity': 'CRITICAL',
            'description': f"RDS instance '{resource_config.get('name')}' has PubliclyAccessible set to True.",
            'threat_context': 'Exposes relational database endpoints directly on internet public IP addresses.',
            'recommendation': 'Set PubliclyAccessible to False and isolate the RDS instance inside a private database subnet.'
        })

    # Check 2: Storage Encryption
    if not resource_config.get('storage_encrypted', True):
        findings.append({
            'rule_id': 'RDS_ENCRYPTION_DISABLED',
            'title': 'RDS Storage Encryption Disabled',
            'severity': 'HIGH',
            'description': f"Database '{resource_config.get('name')}' database storage and automated backups are unencrypted.",
            'threat_context': 'Data at rest, transaction logs, and snapshots can be read if storage volumes are extracted.',
            'recommendation': 'Enable KMS storage encryption during database creation or snapshot restore.'
        })

    # Check 3: Multi-AZ Deployment
    if not resource_config.get('multi_az', False):
        findings.append({
            'rule_id': 'RDS_NO_MULTI_AZ',
            'title': 'RDS Instance Lacks Multi-AZ High Availability',
            'severity': 'LOW',
            'description': f"RDS database '{resource_config.get('name')}' is deployed as a Single-AZ instance.",
            'threat_context': 'Single points of failure reduce resilience against availability zone outages or underlying host failures.',
            'recommendation': 'Enable Multi-AZ deployment for production database instances.'
        })

    return findings

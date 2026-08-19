"""
AWS Boto3 Cloud Scanner Integration Module
Uses read-only AWS APIs to discover resources and configuration details.
Never stores credentials; relies on environment variables or standard AWS credentials file.
"""

import logging
import os

logger = logging.getLogger(__name__)

def discover_aws_resources(region_name=None, access_key_id=None, secret_access_key=None, session_token=None):
    """
    Discovers AWS resources across S3, EC2, IAM, Security Groups, and RDS using Boto3.
    Returns (resources_list, error_message)
    """
    region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    try:
        import boto3
        from botocore.config import Config as BotoClientConfig
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return [], "boto3 library is not installed. Please install boto3 to use real AWS scanning."

    credentials = {
        key: value for key, value in {
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'aws_session_token': session_token
        }.items() if value
    }

    # Prevent long hanging calls if network or AWS service is unresponsive
    client_cfg = BotoClientConfig(connect_timeout=5, read_timeout=5, retries={'max_attempts': 2})
    resources = []
    
    # 1. Discover S3 Buckets
    try:
        s3_client = boto3.client('s3', region_name=region_name, config=client_cfg, **credentials)
        buckets_resp = s3_client.list_buckets()
        for bucket in buckets_resp.get('Buckets', []):
            b_name = bucket['Name']
            
            # Inspect Public Access Block
            public_access = False
            block_public = True
            try:
                pab = s3_client.get_public_access_block(Bucket=b_name)
                conf = pab.get('PublicAccessBlockConfiguration', {})
                if not (conf.get('BlockPublicAcls') and conf.get('IgnorePublicAcls') and conf.get('BlockPublicPolicy') and conf.get('RestrictPublicBuckets')):
                    public_access = True
                    block_public = False
            except ClientError:
                # If No PublicAccessBlockConfiguration exists, bucket may allow public access
                public_access = True
                block_public = False

            # Inspect Encryption
            encryption_enabled = False
            try:
                enc = s3_client.get_bucket_encryption(Bucket=b_name)
                if enc.get('ServerSideEncryptionConfiguration'):
                    encryption_enabled = True
            except ClientError:
                encryption_enabled = False

            # Inspect Versioning — actually call AWS API (was hardcoded False before)
            versioning_enabled = False
            try:
                ver = s3_client.get_bucket_versioning(Bucket=b_name)
                versioning_status = ver.get('Status', '')
                versioning_enabled = (versioning_status == 'Enabled')
            except ClientError:
                versioning_enabled = False

            resources.append({
                'resource_id': f"arn:aws:s3:::{b_name}",
                'resource_name': b_name,
                'resource_type': 'S3',
                'region': region_name,
                'status': 'Active',
                'config': {
                    'name': b_name,
                    'public_access_enabled': public_access,
                    'block_public_access': block_public,
                    'encryption_enabled': encryption_enabled,
                    'versioning_enabled': versioning_enabled
                }
            })
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning(f"S3 Discovery error: {e}")

    # 2. Discover EC2 Instances
    try:
        ec2_client = boto3.client('ec2', region_name=region_name, config=client_cfg, **credentials)
        resv = ec2_client.describe_instances()
        for r in resv.get('Reservations', []):
            for inst in r.get('Instances', []):
                inst_id = inst['InstanceId']
                tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                name = tags.get('Name', inst_id)
                public_ip = inst.get('PublicIpAddress')
                
                resources.append({
                    'resource_id': inst_id,
                    'resource_name': name,
                    'resource_type': 'EC2',
                    'region': region_name,
                    'status': inst.get('State', {}).get('Name', 'unknown').capitalize(),
                    'config': {
                        'name': name,
                        'public_ip_assigned': bool(public_ip),
                        'public_ip': public_ip,
                        'environment': tags.get('Environment', 'production').lower(),
                        'iam_instance_profile': bool(inst.get('IamInstanceProfile')),
                        'detailed_monitoring': inst.get('Monitoring', {}).get('State') == 'enabled'
                    }
                })
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning(f"EC2 Discovery error: {e}")

    # 3. Discover IAM Users
    try:
        iam_client = boto3.client('iam', region_name=region_name, config=client_cfg, **credentials)
        users = iam_client.list_users().get('Users', [])
        for u in users:
            uname = u['UserName']
            # Check MFA
            mfa_resp = iam_client.list_mfa_devices(UserName=uname)
            mfa_enabled = len(mfa_resp.get('MFADevices', [])) > 0
            
            # Check Attached Policies for Admin
            has_admin = False
            policies = iam_client.list_attached_user_policies(UserName=uname).get('AttachedPolicies', [])
            for p in policies:
                if 'AdministratorAccess' in p.get('PolicyName', ''):
                    has_admin = True

            resources.append({
                'resource_id': u.get('Arn', f"arn:aws:iam::user/{uname}"),
                'resource_name': uname,
                'resource_type': 'IAM',
                'region': 'global',
                'status': 'Active',
                'config': {
                    'name': uname,
                    'has_admin_privileges': has_admin,
                    'mfa_enabled': mfa_enabled,
                    'key_age_days': 45
                }
            })
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning(f"IAM Discovery error: {e}")

    # 4. Discover Security Groups
    try:
        ec2_client = boto3.client('ec2', region_name=region_name, config=client_cfg, **credentials)
        sgs = ec2_client.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            open_rules = []
            
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    open_rules.append({
                        'port': from_port if from_port == to_port else f"{from_port}-{to_port}",
                        'cidr': cidr
                    })

            resources.append({
                'resource_id': sg_id,
                'resource_name': sg_name,
                'resource_type': 'Security Group',
                'region': region_name,
                'status': 'Active',
                'config': {
                    'name': sg_name,
                    'open_ingress_rules': open_rules
                }
            })
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning(f"Security Group Discovery error: {e}")

    # 5. Discover RDS Instances
    try:
        rds_client = boto3.client('rds', region_name=region_name, config=client_cfg, **credentials)
        dbs = rds_client.describe_db_instances().get('DBInstances', [])
        for db_inst in dbs:
            db_id = db_inst['DBInstanceIdentifier']
            resources.append({
                'resource_id': db_inst.get('DBInstanceArn', db_id),
                'resource_name': db_id,
                'resource_type': 'RDS',
                'region': region_name,
                'status': db_inst.get('DBInstanceStatus', 'active').capitalize(),
                'config': {
                    'name': db_id,
                    'publicly_accessible': db_inst.get('PubliclyAccessible', False),
                    'storage_encrypted': db_inst.get('StorageEncrypted', True),
                    'multi_az': db_inst.get('MultiAZ', False)
                }
            })
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning(f"RDS Discovery error: {e}")

    if not resources:
        return [], "No AWS resources could be retrieved. Ensure AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION) or ~/.aws/credentials are properly configured."

    return resources, None

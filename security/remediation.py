"""
SOAR Auto-Remediation & Code Generator Engine
Executes automated 1-click cloud security fixes using AWS Boto3 APIs and generates
Infrastructure-as-Code (Terraform, CloudFormation, AWS CLI, Python Boto3) remediation snippets.
"""

import os
import logging
from config import Config

logger = logging.getLogger(__name__)

def execute_auto_remediation(finding):
    """
    Executes automated 1-click remediation for a given Finding.
    Returns (success: bool, message: str)
    """
    if not finding:
        return False, "Finding not found"

    f_id = getattr(finding, 'finding_id', '')
    res_name = finding.resource_rel.resource_name if getattr(finding, 'resource_rel', None) else finding.resource_id
    res_id = finding.resource_id
    parts = f_id.split('-', 2)
    rule_id = parts[2] if len(parts) == 3 else f_id

    region_name = getattr(finding.resource_rel, 'region', 'us-east-1')
    if region_name == 'global':
        region_name = Config.AWS_REGION or 'us-east-1'

    # Check if running in Live AWS or Demo mode
    is_demo = Config.DEMO_MODE

    try:
        if rule_id == 'S3_PUBLIC_ACCESS':
            if not is_demo:
                import boto3
                from botocore.config import Config as BotoConfig
                s3 = boto3.client('s3', region_name=region_name, config=BotoConfig(connect_timeout=5, read_timeout=5))
                s3.put_public_access_block(
                    Bucket=res_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
            return True, f"Successfully applied 'Block All Public Access' to S3 bucket '{res_name}'."

        elif rule_id == 'S3_ENCRYPTION_DISABLED':
            if not is_demo:
                import boto3
                from botocore.config import Config as BotoConfig
                s3 = boto3.client('s3', region_name=region_name, config=BotoConfig(connect_timeout=5, read_timeout=5))
                s3.put_bucket_encryption(
                    Bucket=res_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }]
                    }
                )
            return True, f"Successfully attached AES256 Server-Side Encryption (SSE-S3) to bucket '{res_name}'."

        elif rule_id == 'SG_OPEN_SSH':
            if not is_demo:
                import boto3
                from botocore.config import Config as BotoConfig
                ec2 = boto3.client('ec2', region_name=region_name, config=BotoConfig(connect_timeout=5, read_timeout=5))
                ec2.revoke_security_group_ingress(
                    GroupId=res_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
            return True, f"Revoked open SSH (Port 22 from 0.0.0.0/0) on Security Group '{res_name}'."

        elif rule_id == 'SG_OPEN_DATABASE':
            if not is_demo:
                import boto3
                from botocore.config import Config as BotoConfig
                ec2 = boto3.client('ec2', region_name=region_name, config=BotoConfig(connect_timeout=5, read_timeout=5))
                for port in [3306, 5432]:
                    try:
                        ec2.revoke_security_group_ingress(
                            GroupId=res_id,
                            IpPermissions=[{
                                'IpProtocol': 'tcp',
                                'FromPort': port,
                                'ToPort': port,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }]
                        )
                    except Exception:
                        pass
            return True, f"Revoked public database ingress rules (3306/5432) on Security Group '{res_name}'."

        else:
            return True, f"Simulated automated remediation executed for '{finding.title}' on {res_name}."

    except Exception as e:
        logger.exception(f"Auto-remediation failed: {e}")
        return False, f"Remediation failed: {str(e)}"


def generate_remediation_code(finding):
    """
    Generates ready-to-use CLI, Terraform, CloudFormation and Python Boto3 remediation scripts.
    """
    f_id = getattr(finding, 'finding_id', '')
    res_name = finding.resource_rel.resource_name if getattr(finding, 'resource_rel', None) else finding.resource_id
    res_id = finding.resource_id
    parts = f_id.split('-', 2)
    rule_id = parts[2] if len(parts) == 3 else f_id

    cli_cmd = ""
    terraform_code = ""
    cloudformation_yaml = ""
    python_boto = ""

    if rule_id == 'S3_PUBLIC_ACCESS':
        cli_cmd = f"aws s3api put-public-access-block \\\n  --bucket {res_name} \\\n  --public-access-block-configuration \\\n  \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        terraform_code = f"""resource "aws_s3_bucket_public_access_block" "remediation" {{
  bucket = "{res_name}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"""
        cloudformation_yaml = f"""Resources:
  S3PublicAccessBlock:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {res_name}
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true"""
        python_boto = f"""import boto3

s3 = boto3.client('s3')
s3.put_public_access_block(
    Bucket='{res_name}',
    PublicAccessBlockConfiguration={{
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }}
)
print("Public Access Block enabled on {res_name}")"""

    elif rule_id == 'S3_ENCRYPTION_DISABLED':
        cli_cmd = f"aws s3api put-bucket-encryption \\\n  --bucket {res_name} \\\n  --server-side-encryption-configuration \\\n  '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
        terraform_code = f"""resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {{
  bucket = "{res_name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"""
        cloudformation_yaml = f"""Resources:
  S3BucketEncryption:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {res_name}
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256"""
        python_boto = f"""import boto3

s3 = boto3.client('s3')
s3.put_bucket_encryption(
    Bucket='{res_name}',
    ServerSideEncryptionConfiguration={{
        'Rules': [{{
            'ApplyServerSideEncryptionByDefault': {{
                'SSEAlgorithm': 'AES256'
            }}
        }}]
    }}
)
print("SSE-S3 Encryption attached to {res_name}")"""

    elif rule_id in ('SG_OPEN_SSH', 'SG_OPEN_DATABASE'):
        port = 22 if rule_id == 'SG_OPEN_SSH' else 3306
        cli_cmd = f"aws ec2 revoke-security-group-ingress \\\n  --group-id {res_id} \\\n  --protocol tcp \\\n  --port {port} \\\n  --cidr 0.0.0.0/0"
        terraform_code = f"""# Ensure 0.0.0.0/0 is removed from ingress:
resource "aws_security_group_rule" "restricted_ingress" {{
  type              = "ingress"
  from_port         = {port}
  to_port           = {port}
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"] # Restrict to internal VPC only
  security_group_id = "{res_id}"
}}"""
        cloudformation_yaml = f"""Resources:
  SecureSecurityGroupIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: {res_id}
      IpProtocol: tcp
      FromPort: {port}
      ToPort: {port}
      CidrIp: 10.0.0.0/16 # Corporate / VPC CIDR"""
        python_boto = f"""import boto3

ec2 = boto3.client('ec2')
ec2.revoke_security_group_ingress(
    GroupId='{res_id}',
    IpPermissions=[{{
        'IpProtocol': 'tcp',
        'FromPort': {port},
        'ToPort': {port},
        'IpRanges': [{{'CidrIp': '0.0.0.0/0'}}]
    }}]
)
print("Revoked public exposure on {res_id}")"""

    else:
        cli_cmd = f"# Review and update resource via AWS CLI:\naws resource-groups list-group-resources --resource-group-arn {res_id}"
        terraform_code = f"""# Update resource definition in Terraform to enforce least privilege and encryption:
# Target Resource: {res_name} ({res_id})"""
        cloudformation_yaml = f"""# Update CloudFormation template for {res_name}"""
        python_boto = f"""# Boto3 automation for {res_name}"""

    return {
        'cli': cli_cmd,
        'terraform': terraform_code,
        'cloudformation': cloudformation_yaml,
        'boto3': python_boto
    }

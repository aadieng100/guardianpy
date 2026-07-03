import boto3
from botocore.exceptions import ClientError

def audit_s3_buckets(s3_client) -> list:
    """
    Audits S3 buckets for public access configurations.
    """
    findings = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Check Bucket ACL
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    # Check if the URI points to AllUsers (Public)
                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                        findings.append({
                            "resource": f"arn:aws:s3:::{bucket_name}",
                            "type": "S3_Bucket",
                            "severity": "CRITICAL",
                            "issue": f"S3 Bucket '{bucket_name}' has a public ACL configuration.",
                        })
                        break
            except ClientError as e:
                # Handle cases where access is denied or bucket doesn't exist
                continue
                
    except ClientError as e:
        print(f"[-] Error listing S3 buckets: {e}")
        
    return findings

def audit_iam_users(iam_client) -> list:
    """
    Audits IAM users to verify if Multi-Factor Authentication (MFA) is enabled.
    """
    findings = []
    try:
        response = iam_client.list_users()
        users = response.get('Users', [])
        
        for user in users:
            username = user['UserName']
            try:
                mfa_response = iam_client.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get('MFADevices', [])
                
                if not mfa_devices:
                    findings.append({
                        "resource": f"arn:aws:iam:::user/{username}",
                        "type": "IAM_User",
                        "severity": "HIGH",
                        "issue": f"IAM User '{username}' does not have Multi-Factor Authentication (MFA) enabled.",
                    })
            except ClientError as e:
                continue
                
    except ClientError as e:
        print(f"[-] Error listing IAM users: {e}")
        
    return findings

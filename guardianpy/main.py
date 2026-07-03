import sys
import boto3
from moto import mock_aws

from guardianpy.config import Config
from guardianpy.scanners.static import scan_dockerfile, scan_terraform
from guardianpy.scanners.aws_mock import audit_s3_buckets, audit_iam_users
from guardianpy.reporters.markdown import generate_markdown_report

def seed_mock_aws_environment():
    """
    Seeds the in-memory mock AWS environment with both secure 
    and misconfigured cloud resources for testing.
    """
    # Initialize mock AWS clients
    s3_client = boto3.client("s3", region_name="us-east-1")
    iam_client = boto3.client("iam", region_name="us-east-1")

    # 1. Seed S3 Buckets
    # Secure bucket
    s3_client.create_bucket(Bucket="guardianpy-production-data-private")
    
    # Vulnerable bucket with public-read ACL
    s3_client.create_bucket(Bucket="guardianpy-public-exposure-bucket")
    s3_client.put_bucket_acl(
        Bucket="guardianpy-public-exposure-bucket", 
        ACL="public-read"
    )

    # 2. Seed IAM Users
    # Vulnerable user without any MFA devices linked
    iam_client.create_user(UserName="vulnerable-ci-user")

def main():
    print("=" * 60)
    print("🛡️  GUARDIANPY: DevSecOps Static & Cloud Compliance Scanner 🛡️")
    print("=" * 60)

    all_findings = []

    # --- Phase 1: Local Static Application Security Testing (SAST) ---
    print("\n[+] Running Static Code Analysis (Shift-Left SAST)...")
    
    # Scan Dockerfile
    if Config.DEFAULT_DOCKERFILE_PATH:
        print(f" -> Scanning Dockerfile: {Config.DEFAULT_DOCKERFILE_PATH}")
        docker_findings = scan_dockerfile(Config.DEFAULT_DOCKERFILE_PATH)
        all_findings.extend(docker_findings)
        
    # Scan Terraform
    if Config.DEFAULT_TERRAFORM_PATH:
        print(f" -> Scanning Terraform: {Config.DEFAULT_TERRAFORM_PATH}")
        tf_findings = scan_terraform(Config.DEFAULT_TERRAFORM_PATH)
        all_findings.extend(tf_findings)

    # --- Phase 2: Mocked Cloud Infrastructure Audit (CSPM) ---
    print("\n[+] Initializing Mock Cloud Environment & Running CSPM Audit...")
    
    # Using Moto's context manager to fully isolate AWS interactions locally
    with mock_aws():
        # Spin up our fake infrastructure
        seed_mock_aws_environment()
        
        # Instantiate clients inside the active mock context
        s3_client = boto3.client("s3", region_name="us-east-1")
        iam_client = boto3.client("iam", region_name="us-east-1")
        
        # Run compliance rules
        all_findings.extend(audit_s3_buckets(s3_client))
        all_findings.extend(audit_iam_users(iam_client))

    # --- Phase 3: Results Aggregation & Display ---
    print("\n" + "=" * 60)
    print(f"📊 SCAN RESULTS: Found {len(all_findings)} issues.")
    print("=" * 60)

    fail_pipeline = False
    severity_weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    failure_threshold = severity_weights.get(Config.FAIL_ON_SEVERITY, 2)

    for finding in all_findings:
        sev = finding.get("severity", "MEDIUM")
        # Determine if this finding breaks the Gatekeeper threshold
        current_weight = severity_weights.get(sev, 1)
        if current_weight >= failure_threshold:
            fail_pipeline = True

        # Render static vs cloud findings cleanly
        if "file" in finding:
            print(f"[{sev}] File: {finding['file']} (Line {finding['line']})")
        else:
            print(f"[{sev}] Resource: {finding['resource']} ({finding['type']})")
            
        print(f"      Issue: {finding['issue']}\n")

    # --- Phase 3.5: Report Generation ---
    print("\n[+] Generating local security report...")
    report_file = generate_markdown_report(all_findings)
    print(f" -> Markdown report successfully written to: {report_file}")

    # --- Phase 4: Gatekeeper Enforcement ---
    print("=" * 60)
    if fail_pipeline:
        print("❌ [GATEKEEPER BLOCKED] Critical/High vulnerabilities detected.")
        print("Stopping process execution with Exit Code 1.")
        print("=" * 60)
        sys.exit(1)
    else:
        print("✅ [GATEKEEPER PASSED] No blocking vulnerabilities found.")
        print("Process completed successfully with Exit Code 0.")
        print("=" * 60)
        sys.exit(0)

if __name__ == "__main__":
    main()

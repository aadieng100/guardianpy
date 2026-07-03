import os
from datetime import datetime

def generate_markdown_report(findings: list, output_path: str = "guardianpy_report.md") -> str:
    """
    Generates a structured Markdown security report from the scanner findings.
    """
    total_issues = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    
    status = "❌ FAILED" if (critical_count + high_count) > 0 else "✅ PASSED"
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    md_content = f"""# 🛡️ GuardianPy Security Report

Generated on: `{current_time}`  
Pipeline Status: **{status}**

## 📊 Executive Summary

| Metric | Summary |
| :--- | :--- |
| **Total Vulnerabilities** | {total_issues} |
| 🔴 Critical Severity | {critical_count} |
| 🟠 High Severity | {high_count} |
| 🟡 Medium Severity | {medium_count} |

---

## 🔍 Detailed Findings

"""

    if total_issues == 0:
        md_content += "✅ No security misconfigurations or vulnerabilities were detected.\n"
    else:
        md_content += "| Severity | Target / Resource | Issue Description | Location / Details |\n"
        md_content += "| :--- | :--- | :--- | :--- |\n"
        
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            # Wrap severity with emojis for better visualization in GitHub UI
            sev_emoji = "🔴 CRITICAL" if severity == "CRITICAL" else "🟠 HIGH" if severity == "HIGH" else "🟡 MEDIUM"
            
            issue = finding.get("issue", "No description provided.")
            
            # Check if it's a static file finding or a cloud resource finding
            if "file" in finding:
                target = f"`{finding['file']}`"
                details = f"Line {finding['line']}"
            else:
                target = f"`{finding['type']}`"
                details = f"ID: {finding['resource']}"
                
            md_content += f"| {sev_emoji} | {target} | {issue} | {details} |\n"

    # Write report to disk
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    return os.path.abspath(output_path)

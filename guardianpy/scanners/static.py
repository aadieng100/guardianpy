import re
import os

def scan_file_by_lines(filepath: str, rules: list) -> list:
    """
    Generic function that parses a file line by line 
    and applies a set of regex rules.
    """
    findings = []
    if not os.path.exists(filepath):
        return findings

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            clean_line = line.strip()
            # Ignore empty lines or comments
            if not clean_line or clean_line.startswith('#'):
                continue
            
            for rule in rules:
                if re.search(rule['pattern'], clean_line):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "severity": rule['severity'],
                        "issue": rule['issue'],
                        "match": clean_line
                    })
    return findings

def scan_dockerfile(filepath: str) -> list:
    """
    Scans a Dockerfile for common security misconfigurations.
    """
    rules = [
        {
            "pattern": r"FROM\s+.*:latest",
            "severity": "MEDIUM",
            "issue": "Usage of ':latest' tag detected. Prefer pinned versions or content hashes for immutability."
        },
        {
            "pattern": r"ENV\s+.*(KEY|SECRET|PASSWORD|TOKEN).*=",
            "severity": "CRITICAL",
            "issue": "Potential hardcoded secret or API key detected in environment variable."
        }
    ]
    
    findings = scan_file_by_lines(filepath, rules)
    
    # Global contextual check: Verify if USER instruction exists
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if "USER" not in content:
                findings.append({
                    "file": filepath,
                    "line": "Global",
                    "severity": "HIGH",
                    "issue": "No 'USER' instruction detected. The container will run as root by default."
                })
                
    return findings

def scan_terraform(filepath: str) -> list:
    """
    Scans a Terraform (.tf) file for cloud misconfigurations.
    """
    rules = [
        {
            "pattern": r"acl\s*=\s*\"public-read\"",
            "severity": "CRITICAL",
            "issue": "S3 bucket configured with a public ACL ('public-read'). Major data leakage risk."
        }
    ]
    return scan_file_by_lines(filepath, rules)
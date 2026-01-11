cat > README.md << 'EOF'
# AWS Security Group Auditor

**Automated compliance tool for identifying overly permissive AWS security group rules**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

## Overview

This tool automatically scans AWS security groups across all regions to identify rules that allow unrestricted internet access (0.0.0.0/0). It prioritizes findings by severity and maps them to NIST 800-53 Rev 5 security controls for compliance reporting.

**Built for:** Security engineers, compliance teams, and cloud administrators managing AWS environments subject to RMF/NIST requirements.

## Problem Statement

Manual security group audits are:
- **Time-consuming**: Checking hundreds of security groups across 16+ regions
- **Error-prone**: Easy to miss overly permissive rules
- **Inconsistent**: No standardized severity scoring or control mapping

This tool solves these problems with automated, consistent scanning and reporting.

## Features

- **Multi-region scanning** - Checks all AWS regions automatically
- **Severity prioritization** - CRITICAL/HIGH/MEDIUM based on exposed services
- **NIST 800-53 mapping** - Maps findings to AC-4, SC-7, SC-7(5) controls
- **Sensitive port detection** - Flags SSH, RDP, database ports
- **JSON export** - Machine-readable output for integration with other tools
- **Zero configuration** - Uses existing AWS CLI credentials

## Quick Start

### Prerequisites

- Python 3.12 or higher
- AWS CLI configured with credentials
- IAM permissions: `ec2:DescribeSecurityGroups`, `ec2:DescribeRegions`

### Installation
```bash
# Clone the repository
git clone https://github.com/Nisha318/aws-security-group-auditor.git
cd aws-security-group-auditor

# Create virtual environment
python -m venv venv
source venv/Scripts/activate  # Windows Git Bash
# or
source venv/bin/activate       # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### Run the Auditor
```bash
python -m src.aws_security_group_auditor.main
```

## Sample Output
```
Starting AWS Security Group Audit
Regions to scan: 16
============================================================
  Scanning region: us-east-1... Found 2 findings
  Scanning region: us-west-2... Found 0 findings
  ...

============================================================
AWS SECURITY GROUP AUDIT REPORT
============================================================
Generated: 2025-01-11 17:37:38 UTC
Total Findings: 2

Findings by Severity:
  MEDIUM: 2

MEDIUM SEVERITY (2 findings):
------------------------------------------------------------

1. default (sg-0e8f039b73ed0d403)
   Region: us-east-1
   VPC: vpc-0e8f039b73ed0d403
   Issue: Allows unrestricted access (0.0.0.0/0) on tcp ports 80-80
   NIST Controls: AC-4, SC-7, SC-7(5)
   Remediation: Restrict source IP ranges to known networks

Detailed findings saved to: security-findings-20250111-173738.json
```

## Architecture
```
┌─────────────┐
│   Script    │
│   Executes  │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ SecurityGroupAuditor│
│      Class          │
└──────┬──────────────┘
       │
       ├─► Get all AWS regions
       │
       ├─► For each region:
       │   ├─► Connect to EC2
       │   ├─► Get all security groups
       │   └─► Check each rule
       │
       ├─► Assess severity
       │
       └─► Generate report
```

## What It Checks

### Detection Logic

The auditor flags security group rules that:
1. Allow inbound traffic from `0.0.0.0/0` (anywhere on the internet)
2. Are not restricted to specific IP ranges

### Severity Scoring

- **CRITICAL**: Exposes SSH (22), RDP (3389), or database ports (MySQL, PostgreSQL, MongoDB, etc.)
- **HIGH**: Opens 1000+ ports to the internet
- **MEDIUM**: Other unrestricted rules

### NIST 800-53 Rev 5 Control Mapping

| Finding Type | Controls | Rationale |
|--------------|----------|-----------|
| Unrestricted ingress | AC-4 | Information flow enforcement violation |
| Open to 0.0.0.0/0 | SC-7 | Boundary protection weakness |
| Wide port ranges | SC-7(5) | Violates "deny by default" principle |

## Project Structure
```
aws-security-group-auditor/
├── src/
│   └── aws_security_group_auditor/
│       ├── __init__.py           # Package initialization
│       └── main.py               # Core auditing logic
├── tests/                        # Unit tests (future)
├── .github/
│   └── workflows/
│       └── test.yml              # GitHub Actions CI/CD
├── requirements.txt              # Python dependencies
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

## Technology Stack

- **Language**: Python 3.12
- **AWS SDK**: Boto3
- **Config Management**: python-dotenv
- **CI/CD**: GitHub Actions
- **Security Scanning**: Bandit, Safety

## Security Considerations

- **No credentials stored**: Uses AWS credential chain (environment variables, IAM roles, or AWS CLI config)
- **Read-only access**: Only requires `Describe*` permissions
- **No modifications**: Tool does not change any AWS resources
- **Secure CI/CD**: GitHub Actions runs security scans on every commit

## Future Enhancements

- [ ] Automatic remediation (restrict rules or send alerts)
- [ ] Lambda deployment for scheduled scans
- [ ] DynamoDB integration for historical trending
- [ ] IPv6 rule support
- [ ] AWS Security Hub integration
- [ ] Web dashboard for visualizing findings

## Use Cases

### Security Engineers
- Quick compliance checks before audits
- Identifying drift from security baselines
- Evidence for RMF packages

### Cloud Administrators  
- Validating security group configurations
- Onboarding new team members to security standards
- Automated scanning in CI/CD pipelines

### Compliance Teams
- Generating evidence for control implementations
- Periodic security posture assessments
- POAM generation for RMF

## License

MIT License - See LICENSE file for details

## Author

**Nisha**  
Senior Cyber Security Engineer (ISSE) | CISSP | AWS Solutions Architect Associate

- Blog: [nishacloud.com](https://nishacloud.com)
- LinkedIn: [Nisha318](https://linkedin.com/in/nisha318)
- Focus: Cloud security automation, GRC engineering, RMF/NIST 800-53 compliance

## Acknowledgments

Built as part of a portfolio project series focused on bridging compliance expertise with cloud security automation.

---

**Disclaimer**: This tool is for educational and auditing purposes. Always test in non-production environments first and follow your organization's change management processes.
EOF
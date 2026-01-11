# AWS Security Group Auditor

**Automated compliance tool for identifying overly permissive AWS security group rules**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![CI](https://github.com/Nisha318/aws-security-group-auditor/workflows/Security%20Scan%20and%20Lint/badge.svg)](https://github.com/Nisha318/aws-security-group-auditor/actions)

## Table of Contents
- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Features](#features)
- [Real-World Results](#real-world-results)
- [Quick Start](#quick-start)
- [Sample Output](#sample-output)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [What It Checks](#what-it-checks)
- [NIST 800-53 Control Mapping](#nist-800-53-rev-5-control-mapping)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Security Considerations](#security-considerations)
- [Use Cases](#use-cases)
- [Roadmap](#roadmap)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [About the Author](#about-the-author)

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

## Real-World Results

In testing across production-scale AWS environments:
- **Scanned**: 16 AWS regions in ~2 minutes
- **Identified**: Critical misconfigurations that would have become POAMs during RMF authorization
- **Time saved**: 8+ hours of manual review per audit cycle
- **Use case**: Suitable for environments with 100+ security groups across multiple VPCs

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

**Quick Test**: To scan only specific regions (faster testing):
```python
# Edit main.py temporarily:
auditor = SecurityGroupAuditor(regions=['us-east-1', 'us-west-2'])
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

## How It Works

1. **Discovery**: Queries AWS API to dynamically discover all available regions
2. **Collection**: For each region, retrieves all security groups using `describe_security_groups()`
3. **Analysis**: Examines each ingress rule for 0.0.0.0/0 CIDR blocks
4. **Severity Assessment**: Prioritizes findings based on exposed ports and services
5. **Control Mapping**: Maps each finding to relevant NIST 800-53 Rev 5 controls
6. **Reporting**: Generates human-readable console output and machine-parseable JSON

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

**Minimum IAM Policy Required:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    }
  ]
}
```

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

## Roadmap

### High Priority
- [ ] Automatic remediation via Lambda
- [ ] SNS/Slack notifications for critical findings
- [ ] AWS Security Hub integration

### Medium Priority
- [ ] IPv6 rule support
- [ ] Historical trending with DynamoDB
- [ ] Custom severity thresholds

### Nice to Have
- [ ] Web dashboard with visualizations
- [ ] Multi-account scanning (AWS Organizations)
- [ ] Export to CSV/PDF formats

## Troubleshooting

**"NoCredentialsError"**
```bash
aws configure  # Set up your AWS credentials
aws sts get-caller-identity  # Verify access
```

**"UnauthorizedOperation"**
- Ensure your IAM user/role has `ec2:DescribeSecurityGroups` and `ec2:DescribeRegions` permissions

**Slow scanning**
- Reduce regions by passing a specific list: `SecurityGroupAuditor(regions=['us-east-1'])`

**Need help?**
- Open an issue on GitHub
- Check existing issues for solutions

## Contributing

This is a portfolio project, but improvements are welcome!

**Ways to contribute:**
- Report bugs or request features via [Issues](https://github.com/Nisha318/aws-security-group-auditor/issues)
- Submit pull requests for enhancements
- Share your use cases or success stories

**Development setup:**
```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 src/
bandit -r src/
```

## License

MIT License - See LICENSE file for details

---

## About the Author

Built by **Nisha** - Senior Cyber Security Engineer (ISSE) | CISSP | AWS Solutions Architect Associate

Specializing in cloud security automation and bridging compliance frameworks with technical implementation.

**Connect:**
- 📝 Blog: [nishacloud.com](https://nishacloud.com)
- 💼 LinkedIn: [Nisha318](https://linkedin.com/in/nishapmcd)
- 🔐 Focus: RMF/NIST 800-53 compliance automation in AWS environments

---

**Disclaimer**: This tool is for educational and auditing purposes. Always test in non-production environments first and follow your organization's change management processes.
# AWS Security Group Auditor - Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                  Python Script (main.py)                    │
│                    Boto3 SDK Integration                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              AWS API - describe_regions()                   │
│         Dynamically discover all available regions          │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┬─────────────┐
         ▼                       ▼             ▼
┌──────────────┐       ┌──────────────┐  ┌──────────────┐
│  us-east-1   │       │  us-west-2   │  │  eu-west-1   │
│   Region     │  ...  │   Region     │  │   Region     │
└──────┬───────┘       └──────┬───────┘  └──────┬───────┘
       │                      │                 │
       ▼                      ▼                 ▼
┌──────────────┐       ┌──────────────┐  ┌──────────────┐
│  Security    │       │  Security    │  │  Security    │
│  Groups      │       │  Groups      │  │  Groups      │
└──────┬───────┘       └──────┬───────┘  └──────┬───────┘
       │                      │                 │
       └──────────────────────┴─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Analysis Engine                          │
│  • Check for 0.0.0.0/0 rules                               │
│  • Identify sensitive port exposure (SSH, RDP, DBs)        │
│  • Assess severity (CRITICAL/HIGH/MEDIUM)                  │
│  • Map to NIST 800-53 controls (AC-4, SC-7, SC-7(5))      │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
┌──────────────────┐   ┌────────────────────┐
│  Console Report  │   │  JSON Export       │
│  • Summary stats │   │  • Finding details │
│  • By severity   │   │  • NIST mappings   │
│  • Remediation   │   │  • Timestamps      │
└──────────────────┘   └────────────────────┘
```

## Data Flow

1. **Discovery Phase**: Script queries AWS to get all available regions
2. **Scanning Phase**: For each region, retrieves all security groups
3. **Analysis Phase**: Examines each security group rule for violations
4. **Assessment Phase**: Calculates severity based on exposed services
5. **Reporting Phase**: Generates human and machine-readable outputs

## Key Components

### SecurityGroupAuditor Class
- `__init__()`: Initialize AWS connection and region list
- `_get_all_regions()`: Dynamically discover regions
- `audit_region()`: Scan single region for violations
- `_check_security_group()`: Analyze individual security group
- `_assess_severity()`: Determine finding criticality
- `generate_report()`: Format compliance-ready output

### NIST 800-53 Control Mapping
- **AC-4**: Information Flow Enforcement - Unrestricted ingress violations
- **SC-7**: Boundary Protection - Perimeter security weaknesses
- **SC-7(5)**: Deny by Default - Wide port range exposures
EOF
```
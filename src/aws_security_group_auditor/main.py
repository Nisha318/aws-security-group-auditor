"""AWS Security Group Auditor - Identifies overly permissive security group rules."""

import boto3
import json
from datetime import datetime
from typing import List, Dict
from botocore.exceptions import ClientError, NoCredentialsError


class SecurityGroupAuditor:
    """Audits AWS security groups for compliance violations."""
    
    SENSITIVE_PORTS = {
        22: "SSH",
        3389: "RDP", 
        1433: "MS SQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch"
    }
    
    def __init__(self, regions: List[str] = None):
        """Initialize the auditor."""
        try:
            self.ec2_client = boto3.client('ec2')
            self.regions = regions or self._get_all_regions()
        except NoCredentialsError:
            print("ERROR: AWS credentials not configured.")
            print("Run: aws configure")
            raise
    
    def _get_all_regions(self) -> List[str]:
        """Retrieve all available AWS regions."""
        try:
            response = self.ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except ClientError as e:
            print(f"Error fetching regions: {e}")
            return ['us-east-1']
    
    def audit_region(self, region: str) -> List[Dict]:
        """Audit security groups in a specific region."""
        findings = []
        ec2 = boto3.client('ec2', region_name=region)
        
        try:
            print(f"  Scanning region: {region}...", end=" ")
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                sg_findings = self._check_security_group(sg, region)
                findings.extend(sg_findings)
            
            print(f"Found {len(findings)} findings")
                
        except ClientError as e:
            print(f"Error: {e}")
            
        return findings
    
    def _check_security_group(self, sg: Dict, region: str) -> List[Dict]:
        """Check individual security group for overly permissive rules."""
        findings = []
        
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    protocol = rule.get('IpProtocol', 'all')
                    
                    severity, exposed_services = self._assess_severity(from_port, to_port)
                    
                    findings.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'region': region,
                        'group_id': sg['GroupId'],
                        'group_name': sg['GroupName'],
                        'vpc_id': sg.get('VpcId', 'EC2-Classic'),
                        'severity': severity,
                        'protocol': protocol,
                        'port_range': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                        'exposed_services': exposed_services,
                        'finding': f'Allows unrestricted access (0.0.0.0/0) on {protocol} ports {from_port}-{to_port}',
                        'remediation': 'Restrict source IP ranges to known networks',
                        'nist_controls': ['AC-4', 'SC-7', 'SC-7(5)']
                    })
                    
        return findings
    
    def _assess_severity(self, from_port: int, to_port: int) -> tuple:
        """Assess severity based on exposed ports."""
        exposed_services = []
        
        for port, service in self.SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                exposed_services.append(f"{service}({port})")
        
        if exposed_services:
            return "CRITICAL", exposed_services
        elif from_port == 0 and to_port == 65535:
            return "CRITICAL", ["ALL PORTS"]
        elif to_port - from_port > 1000:
            return "HIGH", [f"Wide range ({to_port - from_port + 1} ports)"]
        else:
            return "MEDIUM", []
    
    def audit_all_regions(self) -> List[Dict]:
        """Audit all configured regions."""
        print(f"\nStarting AWS Security Group Audit")
        print(f"Regions to scan: {len(self.regions)}")
        print("=" * 60)
        
        all_findings = []
        
        for region in self.regions:
            findings = self.audit_region(region)
            all_findings.extend(findings)
        
        return all_findings
    
    def generate_report(self, findings: List[Dict]) -> str:
        """Generate a formatted compliance report."""
        report = [
            "\n" + "=" * 60,
            "AWS SECURITY GROUP AUDIT REPORT",
            "=" * 60,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Total Findings: {len(findings)}",
            ""
        ]
        
        severity_counts = {}
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report.append("Findings by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report.append(f"  {severity}: {count}")
        
        report.append("\nDetailed Findings:\n")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in findings if f['severity'] == severity]
            
            if severity_findings:
                report.append(f"\n{severity} SEVERITY ({len(severity_findings)} findings):")
                report.append("-" * 60)
                
                for i, finding in enumerate(severity_findings, 1):
                    report.append(f"\n{i}. {finding['group_name']} ({finding['group_id']})")
                    report.append(f"   Region: {finding['region']}")
                    report.append(f"   VPC: {finding['vpc_id']}")
                    report.append(f"   Issue: {finding['finding']}")
                    if finding['exposed_services']:
                        report.append(f"   Exposed Services: {', '.join(finding['exposed_services'])}")
                    report.append(f"   NIST Controls: {', '.join(finding['nist_controls'])}")
                    report.append(f"   Remediation: {finding['remediation']}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)


def main():
    """Main entry point for the security group auditor."""
    try:
        auditor = SecurityGroupAuditor()
        findings = auditor.audit_all_regions()
        report = auditor.generate_report(findings)
        print(report)
        
        output_file = f"security-findings-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        print(f"\nDetailed findings saved to: {output_file}")
        
        if any(f['severity'] == 'CRITICAL' for f in findings):
            print("\nCRITICAL findings detected!")
            return 1
        
        return 0
        
    except NoCredentialsError:
        print("\nAWS credentials not configured. Run: aws configure")
        return 1
    except Exception as e:
        print(f"\nError: {e}")
        return 1


if __name__ == "__main__":
    exit(main())

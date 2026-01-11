from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.network import VPC
from diagrams.aws.security import SecurityGroup
from diagrams.programming.language import Python
from diagrams.onprem.vcs import Github

graph_attr = {
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.5",
}

with Diagram("AWS Security Group Auditor Architecture", 
             filename="aws_sg_auditor_architecture", 
             show=False,
             graph_attr=graph_attr,
             direction="LR"):
    
    script = Python("Security Group\nAuditor\n(Python/Boto3)")
    
    with Cluster("AWS Account"):
        with Cluster("Region: us-east-1"):
            vpc1 = VPC("VPC")
            sg1 = SecurityGroup("Security\nGroups")
            vpc1 >> sg1
        
        with Cluster("Region: us-west-2"):
            vpc2 = VPC("VPC")
            sg2 = SecurityGroup("Security\nGroups")
            vpc2 >> sg2
        
        with Cluster("Region: us-west-1"):
            vpc3 = VPC("VPC")
            sg3 = SecurityGroup("Security\nGroups")
            vpc3 >> sg3
    
    github = Github("GitHub Actions\nCI/CD")
    
    script >> Edge(label="Scan All Regions") >> [sg1, sg2, sg3]
    script >> Edge(label="Generate Report\n+ NIST Mapping") >> github

print("Diagram created: aws_sg_auditor_architecture.png")

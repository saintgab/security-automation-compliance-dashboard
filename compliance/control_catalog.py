"""
Control catalog: maps each AWS Security Hub control this pipeline monitors
(same 12 controls as AWS_Security_Baseline.docx, Appendix A) to the SOC 2
Trust Services Criteria and ISO/IEC 27001:2022 Annex A reference an auditor
would actually ask for. This is the piece that turns "we have a dashboard"
into "we have mapped, evidenced controls" -- which is the entire point of
a Drata-style evidence tool.
"""

CONTROL_CATALOG = [
    {
        "control_id": "IAM.1",
        "control_name": "Root account has no active access keys",
        "requirement": "The AWS root user must not have active programmatic access keys; all administrative access uses named IAM identities with MFA.",
        "soc2_criteria": ["CC6.1"],
        "iso27001_ref": ["A.5.15", "A.5.18"],
    },
    {
        "control_id": "IAM.22",
        "control_name": "Unused IAM credentials disabled",
        "requirement": "IAM credentials unused for more than 90 days are disabled to reduce standing access risk.",
        "soc2_criteria": ["CC6.1", "CC6.2"],
        "iso27001_ref": ["A.5.18"],
    },
    {
        "control_id": "CloudTrail.1",
        "control_name": "CloudTrail enabled in all regions",
        "requirement": "Account activity is logged across every region with log file validation enabled.",
        "soc2_criteria": ["CC7.2"],
        "iso27001_ref": ["A.8.15", "A.8.16"],
    },
    {
        "control_id": "GuardDuty.1",
        "control_name": "GuardDuty threat detection enabled",
        "requirement": "Continuous automated threat detection is active in every region in use.",
        "soc2_criteria": ["CC6.8", "CC7.1"],
        "iso27001_ref": ["A.8.16"],
    },
    {
        "control_id": "Config.1",
        "control_name": "AWS Config recording enabled",
        "requirement": "AWS Config records configuration changes for all supported resource types, supporting change management evidence.",
        "soc2_criteria": ["CC7.1", "CC8.1"],
        "iso27001_ref": ["A.8.9", "A.8.32"],
    },
    {
        "control_id": "KMS.4",
        "control_name": "KMS key rotation enabled",
        "requirement": "Customer-managed KMS keys rotate automatically at least annually.",
        "soc2_criteria": ["CC6.7"],
        "iso27001_ref": ["A.8.24"],
    },
    {
        "control_id": "VPC.1",
        "control_name": "Default security group restricts traffic",
        "requirement": "Default VPC security groups deny all inbound/outbound traffic by default.",
        "soc2_criteria": ["CC6.6"],
        "iso27001_ref": ["A.8.20"],
    },
    {
        "control_id": "EC2.19",
        "control_name": "No unrestricted SSH/RDP ingress",
        "requirement": "No security group permits unrestricted (0.0.0.0/0) inbound SSH or RDP access.",
        "soc2_criteria": ["CC6.6"],
        "iso27001_ref": ["A.8.20"],
    },
    {
        "control_id": "S3.8",
        "control_name": "S3 Block Public Access enabled",
        "requirement": "S3 buckets block public access at the bucket and account level.",
        "soc2_criteria": ["CC6.1", "CC6.6"],
        "iso27001_ref": ["A.5.15", "A.8.20"],
    },
    {
        "control_id": "EC2.8",
        "control_name": "IMDSv2 required",
        "requirement": "EC2 instances require IMDSv2, disabling the more exploitable IMDSv1 metadata endpoint.",
        "soc2_criteria": ["CC6.6"],
        "iso27001_ref": ["A.8.9"],
    },
    {
        "control_id": "Lambda.1",
        "control_name": "No public Lambda invoke access",
        "requirement": "Lambda function resource policies do not grant public or anonymous invoke access.",
        "soc2_criteria": ["CC6.1", "CC6.6"],
        "iso27001_ref": ["A.8.20"],
    },
    {
        "control_id": "RDS.3",
        "control_name": "RDS encrypted at rest",
        "requirement": "RDS instances and snapshots are encrypted at rest using a KMS key.",
        "soc2_criteria": ["CC6.7"],
        "iso27001_ref": ["A.8.24"],
    },
]

import boto3

def scan_security_groups():
    ec2 = boto3.client('ec2')
    findings = []

    response = ec2.describe_security_groups()

    for sg in response['SecurityGroups']:
        for rule in sg['IpPermissions']:
            for ip in rule.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    findings.append({
                        "service": "EC2",
                        "resource": sg['GroupId'],
                        "issue": "Security Group open to the world",
                        "severity": "High",
                        "risk_score": 30
                    })

    return findings

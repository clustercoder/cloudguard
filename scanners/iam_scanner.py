import boto3
from datetime import datetime, timezone

def scan_iam():
    iam = boto3.client('iam')
    findings = []

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']

        # Admin access check
        policies = iam.list_attached_user_policies(UserName=username)
        for policy in policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AdministratorAccess':
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "issue": "Administrator Access Assigned",
                    "severity": "Critical",
                    "risk_score": 40
                })

        # Inactive user check
        last_used = iam.get_user(UserName=username)['User'].get('PasswordLastUsed')
        if last_used:
            days_inactive = (datetime.now(timezone.utc) - last_used).days
            if days_inactive > 90:
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "issue": "Inactive IAM User (>90 days)",
                    "severity": "Medium",
                    "risk_score": 15
                })

    return findings

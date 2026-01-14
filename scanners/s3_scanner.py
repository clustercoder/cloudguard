import boto3

def scan_public_s3():
    s3 = boto3.client('s3')
    findings = []

    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant):
                    findings.append({
                        "service": "S3",
                        "resource": name,
                        "issue": "Public S3 Bucket",
                        "severity": "High",
                        "risk_score": 50
                    })
        except Exception:
            pass

    return findings

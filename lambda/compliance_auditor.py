import boto3
import json
import datetime

ec2 = boto3.client('ec2')
iam = boto3.client('iam')
s3 = boto3.client('s3')
sns = boto3.client('sns')

S3_BUCKET = "cloud-compliance-reports-AWS"
SNS_TOPIC_ARN = "compliance-alert-topic"

def check_security_groups():
    findings = []
    groups = ec2.describe_security_groups()['SecurityGroups']

    for sg in groups:
        for perm in sg.get('IpPermissions', []):
            for ip in perm.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    if perm.get('FromPort') in [22, 3389]:
                        findings.append({
                            "service": "EC2",
                            "resource_id": sg['GroupId'],
                            "issue": "Sensitive port open to world",
                            "severity": "Critical"
                        })
    return findings


def check_ebs_encryption():
    findings = []
    volumes = ec2.describe_volumes()['Volumes']

    for vol in volumes:
        if not vol['Encrypted']:
            findings.append({
                "service": "EBS",
                "resource_id": vol['VolumeId'],
                "issue": "Unencrypted EBS volume",
                "severity": "Medium"
            })
    return findings


def check_iam_mfa():
    findings = []
    users = iam.list_users()['Users']

    for user in users:
        mfa = iam.list_mfa_devices(UserName=user['UserName'])
        if not mfa['MFADevices']:
            findings.append({
                "service": "IAM",
                "resource_id": user['UserName'],
                "issue": "User without MFA",
                "severity": "High"
            })
    return findings


def lambda_handler(event, context):

    findings = []
    findings.extend(check_security_groups())
    findings.extend(check_ebs_encryption())
    findings.extend(check_iam_mfa())

    report = {
        "date": str(datetime.datetime.utcnow()),
        "total_findings": len(findings),
        "details": findings
    }

    file_name = f"report-{datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M')}.json"

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=file_name,
        Body=json.dumps(report, indent=4)
    )

    if findings:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Compliance Alert",
            Message=json.dumps(report, indent=2)
        )

    return report

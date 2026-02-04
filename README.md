# AWS Serverless Cloud Security Compliance Auditor
Serverless Cloud Security Compliance Auditor using AWS Lambda, EventBridge, SNS and S3.

## Overview

This project implements a serverless cloud security auditing solution using AWS Lambda, EventBridge, SNS, and S3.

The system automatically scans AWS resources for common security misconfigurations and generates compliance reports.


## Architecture

EventBridge (Scheduled Trigger)
        ↓
AWS Lambda (Security Checks)
        ↓
S3 (Compliance Report Storage)
        ↓
SNS (Alert Notification)

## Security Checks Implemented

- Security Groups exposing SSH (22) or RDP (3389) to 0.0.0.0/0
- Unencrypted EBS Volumes
- IAM Users without MFA


## AWS Services Used

- AWS Lambda
- Amazon EventBridge
- Amazon SNS
- Amazon S3
- IAM


## Execution Flow

1. EventBridge triggers Lambda on a schedule.
2. Lambda scans AWS services using boto3.
3. Findings are structured into a JSON report.
4. Report is stored in S3.
5. SNS sends alert if issues are detected.


## Deployment Steps

### Phase 1 – Architecture Setup
- Create S3 bucket for reports
- Create SNS topic + subscription
- Create IAM role with least privilege

### Phase 2 – Lambda Deployment
- Create Lambda function
- Attach IAM role
- Upload Python code

### Phase 3 – Testing
- Create test event
- Verify S3 report generation
- Verify SNS email alert

### Phase 4 – Automation
- Create EventBridge scheduled rule
- Attach Lambda as target


## Improvements (Future Enhancements)

- Add S3 public bucket detection
- Add severity classification
- Add auto-remediation
- Convert infrastructure to Terraform
- Multi-account scanning using AssumeRole


## Author

Mohammad Sohail Khan

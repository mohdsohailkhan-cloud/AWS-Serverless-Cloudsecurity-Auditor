# Architecture Explanation

The system follows an event-driven serverless architecture.

## Components

- EventBridge: Schedules compliance scans.
- Lambda: Executes security checks.
- S3: Stores structured compliance reports.
- SNS: Sends alerts when findings exist.

## Design Principles

- Modular Security Check Functions
- Serverless Cost Optimization
- Automated Governance


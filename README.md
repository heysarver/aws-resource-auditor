# AWS Resource Auditor

A Python tool for auditing AWS resources across accounts and sub-accounts within AWS Organizations.

## Features

- **Organization Enumeration**: Identify all accounts within your AWS Organization
- **Cross-Account Auditing**: Audit resources across all accounts in your organization
- **EC2 Instance Inventory**: Collect information about EC2 instances
- **EBS Volume Inventory**: Collect information about EBS volumes
- **Unused AMI Detection**: Identify unused AMIs that may be incurring costs
- **High-Cost Services Inventory**: Identify potentially high-cost services:
  - Elastic Load Balancers (ELB)
  - NAT Gateways
  - S3 Buckets
  - RDS Instances
- **Multithreaded Processing**: Parallel processing of accounts and regions for faster auditing
- **CSV Reporting**: Generate CSV reports for easy import into dashboards
- **Logging**: Maintain local logs for audit tracking

## Installation

### Automated Setup

Run the setup script to create a virtual environment, install dependencies, and create necessary directories:

```bash
./setup.sh
```

### Manual Setup

If you prefer to set up manually:

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create logs and reports directories:
   ```bash
   mkdir -p logs reports
   ```

## Usage

Run the AWS Resource Auditor using the wrapper script:

```bash
./aws-auditor.sh [options]
```

### Options

- `--profile PROFILE`: AWS profile to use (default: default)
- `--role ROLE`: Role to assume when switching organizations
- `--regions REGIONS`: Comma-separated list of AWS regions to scan (default: all regions)
- `--services SERVICES`: Comma-separated list of services to audit (default: all services)
- `--audit-all-accounts`: Audit all accounts in the organization (requires --role)
- `--max-workers N`: Maximum number of worker threads for parallel processing (default: 5)
- `--help`: Display help message and exit

### Examples

Audit EC2 and S3 resources in specific regions using a custom profile:
```bash
./aws-auditor.sh --profile myprofile --regions us-east-1,us-west-2 --services ec2,s3
```

Audit all resources across all accounts in your organization:
```bash
./aws-auditor.sh --profile myprofile --role AuditRole --audit-all-accounts
```

Audit all accounts with increased parallelism (10 worker threads):
```bash
./aws-auditor.sh --profile myprofile --role AuditRole --audit-all-accounts --max-workers 10
```

## Reports

Reports are generated in the `reports` directory with timestamps in the filenames. For cross-account auditing, both individual account reports and consolidated reports are generated.

## Logs

Logs are stored in the `logs` directory with timestamps in the filenames.

## Requirements

- Python 3.6+
- AWS CLI configured with appropriate credentials
- Required Python packages (installed via `requirements.txt`):
  - boto3
  - botocore

## IAM Permissions

The AWS user or role used must have the following permissions:
- `organizations:ListAccounts`
- `organizations:DescribeOrganization`
- `sts:AssumeRole` (for cross-account auditing)
- Read-only permissions for the services being audited (EC2, EBS, S3, RDS, etc.)

For cross-account auditing, the role being assumed must exist in all accounts and trust the account from which you're running the tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 

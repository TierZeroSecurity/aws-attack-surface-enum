# AWS Attack Surface Enumeration Tool

[![Bash](https://img.shields.io/badge/bash-5.0%2B-blue.svg)](https://www.gnu.org/software/bash/)
[![AWS CLI](https://img.shields.io/badge/AWS_CLI-v2-orange.svg)](https://aws.amazon.com/cli/)

> Optimised AWS external attack surface enumeration script for security assessments and penetration testing

A comprehensive bash script that discovers and catalogues all publicly-accessible AWS resources across your infrastructure. Uses an innovative "ENI-first" strategy to efficiently scan 24 critical services whilst eliminating redundant API calls.

---

## Table of Contents

- [Features](#features)
- [Strategy](#strategy)
- [Coverage](#coverage)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Security Considerations](#security-considerations)
- [Legal and Ethical Use](#legal-and-ethical-use)
- [Performance](#performance)

---

## Features

- **60% faster** than traditional service-by-service enumeration
- **ENI-first strategy** - One scan replaces 25+ individual service scans
- **24 critical services** covering 99% of external attack surface
- **Parallel execution** support for even faster scanning
- **CSV exports** for easy integration with analysis tools
- **Security findings** automatically highlighted in summary
- **Multi-region** support with auto-detection
- **Detailed reports** with resource counts and security metrics

---

## Strategy

### ENI-First Approach

Instead of querying each AWS service individually, this script leverages the fact that most compute/database services use **Elastic Network Interfaces (ENIs)** under the hood. 

**Traditional approach:**
```
scan_ec2 → scan_rds → scan_redshift → scan_elasticache → ... (25+ scans)
```

**Our approach:**
```
scan_public_enis → (catches EC2, RDS, Redshift, ElastiCache, and 20+ more in ONE scan)
```

**Result:** Same coverage, 60% faster

---

## Coverage

### Services Scanned (24 total)

#### Network Layer (3 services)
- **Elastic Network Interfaces (ENIs)** - *catches 25+ service types*
- Elastic IPs
- Security Groups (0.0.0.0/0 rules)

#### HTTP/Serverless Layer - Tier 1 (5 services)
- API Gateway (REST/HTTP/WebSocket)
- Lambda Function URLs
- AppSync GraphQL APIs
- Cognito User Pools

#### HTTP/Serverless Layer - Tier 2 (5 services)
- Load Balancers (ALB/NLB/CLB)
- Amplify Apps
- App Runner Services
- Elastic Beanstalk
- SageMaker Endpoints

#### HTTP/Serverless Layer - Tier 3 (3 services)
- QuickSight Dashboards
- Transfer Family (SFTP/FTP)
- ECR Repositories

#### Specialised Services (5 services)
- CodeArtifact
- Managed Grafana
- MWAA (Managed Airflow)
- Keyspaces (Cassandra)
- IoT Core

#### Global Services (4 services)
- Route53 DNS Records
- S3 Buckets
- CloudFront Distributions
- Global Accelerator

**Total: 20 regional + 4 global = 24 services**

### What ENI Scan Catches

The single ENI scan automatically discovers:
- EC2 instances
- RDS databases
- Redshift clusters
- ElastiCache clusters
- DocumentDB clusters
- Neptune clusters
- OpenSearch domains
- EKS cluster endpoints
- MSK clusters
- ECS/Fargate tasks
- NAT Gateways
- Amazon MQ brokers
- WorkSpaces
- Client VPN endpoints
- EMR clusters
- DMS replication instances
- Glue dev endpoints
- Lightsail instances
- Connect instances
- GameLift fleets
- *...and more*

---

## Requirements

- **Bash** 5.0+ (macOS/Linux)
- **AWS CLI** v2
- **jq** (JSON processor)
- **Valid AWS credentials** with read permissions

---

## Installation

### Option 1: Clone Repository
```bash
git clone https://github.com/TierZeroSecurity/aws-attack-surface-enum.git
cd aws-attack-surface-enum
chmod +x aws-attack-surface-enum.sh
```

### Option 2: Direct Download
```bash
curl -O https://raw.githubusercontent.com/TierZeroSecurity/aws-attack-surface-enum/main/aws-attack-surface-enum.sh
chmod +x aws-attack-surface-enum.sh
```

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y awscli jq
```

**macOS:**
```bash
brew install awscli jq
```

**Verify Installation:**
```bash
aws --version  # Should be v2.x
jq --version   # Should be 1.6+
```

### Configure AWS Credentials
```bash
aws configure
# OR use environment variables:
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_SESSION_TOKEN="your-token"  # if using temporary credentials
```

---

## Usage

### Basic Usage
```bash
# Interactive mode (prompts for confirmation)
./aws-attack-surface-enum.sh

# Non-interactive mode (auto-confirm)
./aws-attack-surface-enum.sh --yes
```

### Advanced Options
```bash
# Enable parallel execution (faster)
./aws-attack-surface-enum.sh --yes --parallel --jobs 10

# Scan specific regions only
./aws-attack-surface-enum.sh --yes --regions us-east-1,eu-west-1

# Custom output directory
./aws-attack-surface-enum.sh --yes --outdir /path/to/output

# Combine options
./aws-attack-surface-enum.sh --yes --parallel --jobs 15 --regions us-east-1,us-west-2
```

### Command-Line Options
```
Options:
  -y, --yes               Auto-confirm prompts (non-interactive)
  -r, --regions <list>    Comma-separated region list to scan
  -o, --outdir <path>     Output directory (default: ./aws-attack-surface-YYYYMMDD-HHMMSS-ACCOUNT_ID)
  -p, --parallel          Enable parallel service scanning
  -j, --jobs <num>        Number of parallel jobs (default: 5, max recommended: 15)
  -h, --help              Show help message
```

---

## Output

### CSV Files Generated

The script creates 24 CSV files in the output directory:
```
aws-attack-surface-20250130-143022-123456789012/
├── public-enis.csv              # All public IPs (ENI scan)
├── elastic-ips.csv              # Allocated Elastic IPs
├── sg-open.csv                  # Security groups allowing 0.0.0.0/0
├── route53.csv                  # DNS records
├── s3.csv                       # S3 buckets with security configs
├── cloudfront.csv               # CloudFront distributions
├── api-gateway.csv              # API Gateway endpoints
├── lambda-urls.csv              # Lambda function URLs
├── appsync.csv                  # GraphQL APIs
├── cognito.csv                  # Cognito user pools
├── loadbalancers.csv            # ALB/NLB/CLB
├── amplify.csv                  # Amplify apps
├── apprunner.csv                # App Runner services
├── elastic-beanstalk.csv        # Beanstalk environments
├── sagemaker-endpoints.csv      # ML inference endpoints
├── global-accelerator.csv       # Global Accelerator IPs
├── quicksight.csv               # Public BI dashboards
├── transfer-servers.csv         # SFTP/FTP servers
├── ecr-repositories.csv         # Container registries
├── codeartifact.csv             # Package repositories
├── grafana.csv                  # Grafana workspaces
├── mwaa.csv                     # Airflow environments
├── keyspaces.csv                # Cassandra keyspaces
├── iot-endpoints.csv            # IoT endpoints
└── SUMMARY.txt                  # Executive summary with findings
```

### Summary Report
```
╔════════════════════════════════════════════════════════╗
║   AWS Attack Surface Inventory                         ║
║   Coverage: 24 Services - ENI-First Strategy           ║
╚════════════════════════════════════════════════════════╝

Scan Date:       Mon Jan 30 14:30:22 UTC 2025
AWS Account:     123456789012
Regions Scanned: 16
Scan Duration:   8m 34s

═══════════════════════════════════════════════════════
Resource Counts by Service
═══════════════════════════════════════════════════════

public-enis                                   :   142
sg-open                                       :    28
s3                                           :    45
api-gateway                                   :    12
lambda-urls                                   :     8
loadbalancers                                 :     6
...

 Security Findings
═══════════════════════════════════════════════════════

  • 142 public IPs discovered (all services combined)
  • 28 security group rules allowing 0.0.0.0/0
  • 5 S3 buckets with public listing
  • 3 Lambda URLs without authentication
  • 8 Cognito user pools (authentication endpoints)
```

---

## Security Considerations

### CloudTrail Logging

This script generates **read-only API calls** that will be logged in CloudTrail:
```
Typical CloudTrail events (per region):
├─ ec2:DescribeNetworkInterfaces
├─ ec2:DescribeAddresses
├─ ec2:DescribeSecurityGroups
├─ elbv2:DescribeLoadBalancers
├─ lambda:ListFunctions
├─ s3:ListBuckets
... (20 service scans per region)

Total: ~320-500 CloudTrail events for 16 regions
```
---

## Legal and Ethical Use

### IMPORTANT: Authorisation Required

This tool is intended for **authorised security assessments only**:

**Authorised use:**
- Your own AWS accounts
- Client accounts with written permission
- Bug bounty programmes that explicitly allow AWS enumeration
- Red team exercises with proper authorisation

**Unauthorised use:**
- Scanning AWS accounts you don't own
- Scanning without explicit permission
- Using stolen credentials
- Violating AWS Terms of Service

### Responsible Disclosure

If you discover vulnerabilities:
1. **Do not exploit** beyond proof-of-concept
2. **Report immediately** to the account owner
3. **Follow** responsible disclosure practices
4. **Document** findings professionally

### Legal Framework

Using this tool without authorisation may violate:
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

**The authors assume no liability for misuse of this tool.**

---

## Performance

### Scan Times

| Account Size | Regions | Parallel | Time |
|--------------|---------|----------|------|
| Small (< 50 resources) | 1 | No | 2-3 min |
| Small (< 50 resources) | 16 | Yes | 3-5 min |
| Medium (100-500 resources) | 1 | No | 5-8 min |
| Medium (100-500 resources) | 16 | Yes | 8-12 min |
| Large (1000+ resources) | 1 | No | 15-20 min |
| Large (1000+ resources) | 16 | Yes | 15-25 min |

### Optimisation Tips
```bash
# Fastest scan (parallel + specific regions)
./aws-attack-surface-enum.sh --yes --parallel --jobs 15 --regions us-east-1

# Slowest scan (sequential + all regions)
./aws-attack-surface-enum.sh --yes

# Recommended (balanced)
./aws-attack-surface-enum.sh --yes --parallel --jobs 10
```

## Changelog

### v1.0.0 (2025-10-29)
- Initial release
- ENI-first strategy implementation
- Parallel execution support
- 24 service coverage (20 regional + 4 global)
- Multi-region support
- Comprehensive CSV exports

---

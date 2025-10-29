# AWS Attack Surface Enumeration Tool (v2)

[![License: BSD 2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-blue.svg)](https://www.gnu.org/software/bash/)
[![AWS CLI](https://img.shields.io/badge/AWS_CLI-v2-orange.svg)](https://aws.amazon.com/cli/)

> Comprehensive AWS external attack surface enumeration for security assessments and penetration testing

A production-grade bash script that discovers and catalogues all publicly-accessible AWS resources across your infrastructure. Uses an innovative **"ENI-first"** strategy combined with explicit database enumeration to efficiently scan **33 critical services** whilst eliminating redundant API calls.

---

## Table of Contents

- [Strategy](#strategy)
- [Service Coverage](#service-coverage)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Performance](#performance)
- [Multi-Account Scanning](#multi-account-scanning)
- [Legal and Ethical Use](#legal-and-ethical-use)

---

## Strategy

### ENI-First Approach + Explicit Database Enumeration

Instead of querying each AWS service individually, this script uses a hybrid approach:

1. **ENI scanning** catches most compute resources (EC2, ECS, Lambda in VPC, etc.)
2. **Explicit database enumeration** ensures complete coverage of managed databases

**Our approach:**
```
scan_public_enis → (catches EC2, ECS, Lambda, NAT GW, ALB/NLB, etc.)
+ scan_rds + scan_redshift + scan_opensearch + ... (9 database services)
⚡ Single ENI scan replaces 25+ individual service scans
```
---

## Service Coverage

### 33 Services Total

#### Network Layer (3 services)
- **Elastic Network Interfaces (ENIs)** - *catches 25+ service types automatically*
- Elastic IPs
- Security Groups (0.0.0.0/0 and ::/0 rules)

#### HTTP/Serverless Layer (13 services)

**Tier 1 - Critical (4 services):**
- API Gateway (REST/HTTP/WebSocket)
- Lambda Function URLs
- AppSync GraphQL APIs
- Cognito User Pools

**Tier 2 - High-Value (5 services):**
- Load Balancers (ALB/NLB/CLB)
- Amplify Apps
- App Runner Services
- Elastic Beanstalk
- SageMaker Endpoints

**Tier 3 - Specialised (4 services):**
- QuickSight Dashboards
- Transfer Family (SFTP/FTP/FTPS)
- ECR Repositories (Public & Private)
- CodeArtifact

#### Database Layer (9 services) ⭐ **Complete Coverage**
- **RDS** (MySQL, PostgreSQL, MariaDB, Oracle, SQL Server, Aurora)
- **Redshift** (Data Warehouse)
- **OpenSearch** (Elasticsearch/OpenSearch Service)
- **MSK** (Managed Streaming for Apache Kafka)
- **ElastiCache** (Redis, Memcached)
- **DocumentDB** (MongoDB-compatible)
- **Neptune** (Graph Database)
- **MemoryDB** (Redis-compatible with durability)
- **Timestream** (Time-series Database)

#### Specialised Services (5 services)
- Managed Grafana Workspaces
- MWAA (Managed Airflow)
- Keyspaces (Apache Cassandra)
- IoT Core Endpoints
- Global Accelerator

#### Global Services (4 services)
- Route53 DNS Records
- S3 Buckets (with security posture)
- CloudFront Distributions
- Global Accelerator

**Total: 29 regional + 4 global = 33 services**

### What ENI Scan Catches Automatically

The single ENI scan discovers:
- ✅ EC2 instances
- ✅ ECS/Fargate tasks
- ✅ Lambda functions (in VPC)
- ✅ NAT Gateways
- ✅ VPN endpoints
- ✅ Network Load Balancers (NLB)
- ✅ Some RDS instances with attached ENIs
- ✅ Some Redshift clusters with attached ENIs
- ✅ WorkSpaces
- ✅ EMR clusters
- ✅ GameLift fleets
- ✅ *...and 15+ more service types*

### Why Explicit Database Enumeration?

While many databases use ENIs, explicit enumeration provides:
- **PubliclyAccessible flag** - Critical security information
- **Endpoint details** - Full connection strings
- **Engine versions** - For vulnerability assessment
- **Status information** - Operational state
- **Complete coverage** - Catches databases without ENIs or in edge cases

---

## Requirements

### System Requirements

- **Bash** 5.0+ (macOS/Linux)
- **AWS CLI** v2
- **jq** (JSON processor)
- **timeout** (coreutils)
- **md5sum** or **shasum** (for tmp file naming)

### AWS Permissions

The script requires read-only permissions across services. Use the provided CloudFormation template or this IAM policy:

<details>
<summary>Click to expand IAM Policy</summary>
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetworkEnumeration",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LoadBalancerEnumeration",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DatabaseEnumeration",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "redshift:DescribeClusters",
        "opensearch:ListDomainNames",
        "opensearch:DescribeDomain",
        "kafka:ListClusters",
        "kafka:DescribeCluster",
        "elasticache:DescribeCacheClusters",
        "docdb:DescribeDBInstances",
        "neptune:DescribeDBInstances",
        "memorydb:DescribeClusters",
        "timestream-write:ListDatabases",
        "timestream-query:DescribeEndpoints"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Enumeration",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketWebsite",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudFrontEnumeration",
      "Effect": "Allow",
      "Action": [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution"
      ],
      "Resource": "*"
    },
    {
      "Sid": "APIGatewayEnumeration",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaEnumeration",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunctionUrlConfig"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Route53Enumeration",
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CognitoEnumeration",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:ListUserPools",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AppSyncEnumeration",
      "Effect": "Allow",
      "Action": [
        "appsync:ListGraphqlApis"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AmplifyEnumeration",
      "Effect": "Allow",
      "Action": [
        "amplify:ListApps",
        "amplify:ListDomainAssociations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AppRunnerEnumeration",
      "Effect": "Allow",
      "Action": [
        "apprunner:ListServices",
        "apprunner:DescribeService"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ElasticBeanstalkEnumeration",
      "Effect": "Allow",
      "Action": [
        "elasticbeanstalk:DescribeEnvironments"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SageMakerEnumeration",
      "Effect": "Allow",
      "Action": [
        "sagemaker:ListEndpoints"
      ],
      "Resource": "*"
    },
    {
      "Sid": "QuickSightEnumeration",
      "Effect": "Allow",
      "Action": [
        "quicksight:ListDashboards",
        "quicksight:ListUsers"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TransferEnumeration",
      "Effect": "Allow",
      "Action": [
        "transfer:ListServers",
        "transfer:DescribeServer"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ECREnumeration",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr-public:DescribeRepositories"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CodeArtifactEnumeration",
      "Effect": "Allow",
      "Action": [
        "codeartifact:ListRepositories"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GrafanaEnumeration",
      "Effect": "Allow",
      "Action": [
        "grafana:ListWorkspaces"
      ],
      "Resource": "*"
    },
    {
      "Sid": "MWAAEnumeration",
      "Effect": "Allow",
      "Action": [
        "airflow:ListEnvironments",
        "airflow:GetEnvironment"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KeyspacesEnumeration",
      "Effect": "Allow",
      "Action": [
        "cassandra:Select"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IoTEnumeration",
      "Effect": "Allow",
      "Action": [
        "iot:DescribeEndpoint"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GlobalAcceleratorEnumeration",
      "Effect": "Allow",
      "Action": [
        "globalaccelerator:ListAccelerators"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSGetCallerIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

**Recommended:** Use AWS managed policy `SecurityAudit` + custom policy for additional services.

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
sudo apt-get install -y awscli jq coreutils
```

**macOS:**
```bash
brew install awscli jq coreutils
```

**Verify Installation:**
```bash
aws --version    # Should be v2.x
jq --version     # Should be 1.6+
timeout --version  # Should be present
```

### Configure AWS Credentials
```bash
# Option 1: AWS CLI configuration
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_SESSION_TOKEN="your-token"  # if using temporary credentials

# Option 3: Use AWS profile
export AWS_PROFILE="your-profile-name"
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
# Enable parallel execution (5x faster)
./aws-attack-surface-enum.sh --yes --parallel --jobs 10

# Scan specific regions only
./aws-attack-surface-enum.sh --yes --regions us-east-1,eu-west-1

# Custom output directory
./aws-attack-surface-enum.sh --yes --outdir /path/to/output

# Use specific AWS profile
./aws-attack-surface-enum.sh --yes --profile production

# Assume role for cross-account scanning
./aws-attack-surface-enum.sh --yes \
  --assume-role arn:aws:iam::123456789012:role/SecurityAuditRole

# Combined options (production use case)
./aws-attack-surface-enum.sh --yes \
  --parallel --jobs 15 \
  --regions us-east-1,us-west-2,eu-west-1 \
  --profile prod \
  --assume-role arn:aws:iam::123456789012:role/SecurityAuditRole
```

### Command-Line Options
```
Options:
  -y, --yes               Auto-confirm prompts (non-interactive)
  -r, --regions <list>    Comma-separated region list to scan
  -o, --outdir <path>     Output directory
  -p, --parallel          Enable parallel service scanning
  -j, --jobs <num>        Number of parallel jobs (default: 5, recommended: 10-15)
  --profile <name>        AWS profile to use
  --assume-role <arn>     Assume role ARN for cross-account scanning
  -h, --help              Show help message
```

---

## Output

### Directory Structure
```
aws-attack-surface-20250130-143022-123456789012/
├── raw/                              # Raw JSON API responses (for forensics)
│   ├── public-enis-us-east-1.json
│   ├── rds-us-east-1.json
│   ├── s3-buckets-list.json
│   └── ... (150+ raw JSON files)
│
├── public-enis.csv                   # All public IPs (ENI scan)
├── elastic-ips.csv                   # Allocated Elastic IPs
├── sg-open.csv                       # Security groups allowing 0.0.0.0/0
├── route53.csv                       # DNS records
├── s3.csv                            # S3 buckets with security configs
├── cloudfront.csv                    # CloudFront distributions
├── api-gateway.csv                   # API Gateway endpoints
├── lambda-urls.csv                   # Lambda function URLs
├── appsync.csv                       # GraphQL APIs
├── cognito.csv                       # Cognito user pools
├── loadbalancers.csv                 # ALB/NLB/CLB
├── amplify.csv                       # Amplify apps
├── apprunner.csv                     # App Runner services
├── elastic-beanstalk.csv             # Beanstalk environments
├── sagemaker-endpoints.csv           # ML inference endpoints
├── global-accelerator.csv            # Global Accelerator IPs
├── quicksight.csv                    # Public BI dashboards
├── transfer-servers.csv              # SFTP/FTP servers
├── ecr-repositories.csv              # Container registries
├── codeartifact.csv                  # Package repositories
├── grafana.csv                       # Grafana workspaces
├── mwaa.csv                          # Airflow environments
├── keyspaces.csv                     # Cassandra keyspaces
├── iot-endpoints.csv                 # IoT endpoints
├── rds.csv                           # RDS database instances ⭐
├── redshift.csv                      # Redshift clusters ⭐
├── opensearch.csv                    # OpenSearch domains ⭐
├── msk.csv                           # MSK Kafka clusters ⭐
├── elasticache.csv                   # ElastiCache clusters ⭐
├── docdb.csv                         # DocumentDB instances ⭐
├── neptune.csv                       # Neptune graph databases ⭐ NEW
├── memorydb.csv                      # MemoryDB clusters ⭐ NEW
├── timestream.csv                    # Timestream databases ⭐ NEW
└── SUMMARY.txt                       # Executive summary with findings
```

### Summary Report Example
```
╔════════════════════════════════════════════════════════╗
║   AWS Attack Surface Inventory (v2.1)                  ║
║   Coverage: 33 Services - ENI-First Strategy           ║
╚════════════════════════════════════════════════════════╝

Scan Date:       Mon Jan 30 14:30:22 UTC 2025
AWS Account:     123456789012
Regions Scanned: 16
Scan Duration:   9m 45s

═══════════════════════════════════════════════════════
Resource Counts by Service
═══════════════════════════════════════════════════════

public-enis                                   :   142
rds                                          :    23
redshift                                     :     3
opensearch                                   :     5
sg-open                                      :    28
s3                                          :    45
loadbalancers                                :    12
api-gateway                                  :     8
lambda-urls                                  :     4
...

───────────────────────────────────────────────────────
TOTAL RESOURCES                              :   287
═══════════════════════════════════════════════════════

 Security Findings (quick counts)
═══════════════════════════════════════════════════════

  • 142 public IPs discovered (all services combined)
  • 28 security group rules allowing 0.0.0.0/0 or ::/0
  • 23 RDS instances (check PubliclyAccessible flag)
  • 5 S3 buckets with public listing
  • 3 Lambda URLs without authentication (AuthType=NONE)

═══════════════════════════════════════════════════════

📊 Optimisation Summary
═══════════════════════════════════════════════════════

Strategy: ENI-first approach + explicit database enumerators
  • ENI scan catches many managed resources
  • Added 9 explicit database enumerators for complete coverage
  • Services scanned: 33 (29 regional + 4 global)

═══════════════════════════════════════════════════════
```

### CSV Format Examples

**public-enis.csv:**
```csv
Region,PublicIP,ENI_ID,Description,SecurityGroup,SubnetID,VpcID,ResourceName,State
us-east-1,54.123.45.67,eni-abc123,Primary network interface,sg-xyz789,subnet-123,vpc-456,web-server-1,in-use
```

**rds.csv:**
```csv
Region,DBInstanceIdentifier,Endpoint,PubliclyAccessible,Status
us-east-1,prod-mysql,prod-mysql.abc123.us-east-1.rds.amazonaws.com,true,available
us-east-1,staging-postgres,staging-postgres.xyz789.us-east-1.rds.amazonaws.com,false,available
```

**s3.csv:**
```csv
BucketName,Region,Created,PublicACL,PublicPolicy,PublicAccessBlock,Website,PublicListing
my-bucket,us-east-1,2024-01-15T10:30:00Z,No,No,All-blocked,No,No
public-assets,us-west-2,2023-05-20T14:22:00Z,Yes,Yes,Not-blocked,Yes,Yes
```

---

## Performance

### Scan Times (v2)

| Account Size | Regions | Mode | Duration | Notes |
|--------------|---------|------|----------|-------|
| Small (<50 resources) | 1 | Sequential | 3-4 min | Quick audit |
| Small (<50 resources) | 16 | Parallel (10 jobs) | 4-6 min | Recommended |
| Medium (100-500) | 1 | Sequential | 8-10 min | Thorough |
| Medium (100-500) | 16 | Parallel (10 jobs) | 10-15 min | Best balance |
| Large (1000+) | 1 | Sequential | 20-25 min | Too slow |
| Large (1000+) | 16 | Parallel (15 jobs) | 18-28 min | **Recommended** |

### Multi-Account Performance (150 accounts)

| Configuration | Total Time | Notes |
|---------------|------------|-------|
| Sequential | ~42 hours | Not recommended |
| Parallel (10 jobs) | ~4.2 hours | Good |
| Parallel (15 jobs) | ~2.8 hours | **Recommended** |
| Parallel (20 jobs) | ~2.1 hours | Max throughput |

### Optimisation Tips

**Fastest Scan:**
```bash
# Single region, parallel services
./aws-attack-surface-enum.sh --yes \
  --parallel --jobs 15 \
  --regions us-east-1
# Duration: 2-3 minutes for medium accounts
```

**Balanced (Most Common):**
```bash
# All regions, parallel services
./aws-attack-surface-enum.sh --yes \
  --parallel --jobs 10
# Duration: 10-15 minutes for medium accounts
```

**Thorough:**
```bash
# All regions, high parallelism
./aws-attack-surface-enum.sh --yes \
  --parallel --jobs 15
# Duration: 18-28 minutes for large accounts
```


---

### Debug Mode

Enable verbose output for troubleshooting:
```bash
# Enable bash debug mode
bash -x ./aws-attack-surface-enum.sh --yes --regions us-east-1

# Or modify script temporarily (add after shebang):
set -x  # Enable debug output
```

---

## Multi-Account Scanning

To Do...

For scanning 10-1000+ AWS accounts:

### Quick Overview

**Option 1: AWS Config Profiles** (2-50 accounts)
- Simple setup
- No AWS Organisations required
- Manual credential management

**Option 2: AWS Organisations** (10-1000+ accounts)
- CloudFormation StackSets
- Cross-account IAM roles
- Centralised management
- Resume capability

---


## Legal and Ethical Use

### ⚠️ IMPORTANT: Authorisation Required

This tool is intended for **authorised security assessments only**:

**✅ Authorised use:**
- Your own AWS accounts
- Client accounts with written permission
- Bug bounty programs that explicitly allow AWS enumeration
- Red team exercises with proper authorisation

**❌ Unauthorised use:**
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

**⚠️ The authors assume no liability for misuse of this tool.**

---

## Additional Resources

- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [OWASP Cloud Security Project](https://owasp.org/www-project-cloud-security/)
- [AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)

---

## Quick Start TL;DR
```bash
# Install dependencies (Ubuntu)
sudo apt-get install -y awscli jq coreutils

# Configure AWS
aws configure

# Download script
curl -O https://raw.githubusercontent.com/TierZeroSecurity/aws-attack-surface-enum/main/aws-attack-surface-enum.sh
chmod +x aws-attack-surface-enum.sh

# Run scan (fast mode)
./aws-attack-surface-enum.sh --yes --parallel --jobs 10

# View results
cat aws-attack-surface-*/SUMMARY.txt
```

**That's it!** You now have a comprehensive attack surface inventory of your AWS account.

---


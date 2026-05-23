# Khepra Protocol - AWS GovCloud Deployment

Deploy Khepra Protocol to AWS GovCloud for FedRAMP High / IL4-IL5 compliance.

## Architecture Overview

```
                                 ┌─────────────────────────────────────┐
                                 │         AWS GovCloud VPC            │
                                 │                                     │
    Internet ──► ALB ──────────► │  ┌─────────────┐  ┌─────────────┐  │
                 │               │  │   ECS API   │  │   ECS       │  │
                 │               │  │   (Fargate) │  │   Dashboard │  │
                 │               │  │   :8080     │  │   (Fargate) │  │
                 │               │  └──────┬──────┘  └─────────────┘  │
                 │               │         │                          │
                 │               │         ▼                          │
                 │               │  ┌─────────────┐                   │
                 │               │  │    RDS      │ (optional)        │
                 │               │  │  PostgreSQL │                   │
                 │               │  └─────────────┘                   │
                                 └─────────────────────────────────────┘
```

## Prerequisites

1. **AWS GovCloud Account** with appropriate permissions
2. **AWS CLI v2** configured with GovCloud credentials
3. **Docker Desktop** installed and running
4. **Git** for cloning the repository

### Configure AWS CLI for GovCloud

```bash
# Create a GovCloud profile
aws configure --profile govcloud
# Enter your GovCloud Access Key ID
# Enter your GovCloud Secret Access Key
# Default region: us-gov-west-1
# Default output: json

# Set as default profile
export AWS_PROFILE=govcloud
```

## Quick Start

### Option 1: Automated Deployment (Recommended)

**PowerShell (Windows):**
```powershell
cd aws-govcloud\scripts
.\deploy-govcloud.ps1 -Environment production -Region us-gov-west-1
```

**Bash (Linux/Mac):**
```bash
cd aws-govcloud/scripts
chmod +x deploy-govcloud.sh
./deploy-govcloud.sh production us-gov-west-1
```

### Option 2: Manual Deployment

#### Step 1: Deploy Infrastructure

```bash
aws cloudformation deploy \
  --stack-name khepra-protocol-infrastructure \
  --template-file aws-govcloud/cloudformation/khepra-govcloud-infrastructure.yaml \
  --parameter-overrides \
    ProjectName=khepra-protocol \
    Environment=production \
    EnableFlowLogs=true \
    EnableFIPS=true \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-gov-west-1
```

#### Step 2: Build and Push Docker Images

```bash
# Get ECR repository URIs from stack outputs
API_ECR_URI=$(aws cloudformation describe-stacks \
  --stack-name khepra-protocol-infrastructure \
  --query "Stacks[0].Outputs[?OutputKey=='APIRepositoryUri'].OutputValue" \
  --output text --region us-gov-west-1)

DASHBOARD_ECR_URI=$(aws cloudformation describe-stacks \
  --stack-name khepra-protocol-infrastructure \
  --query "Stacks[0].Outputs[?OutputKey=='DashboardRepositoryUri'].OutputValue" \
  --output text --region us-gov-west-1)

# Login to ECR
aws ecr get-login-password --region us-gov-west-1 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com

# Build and push images
docker build -t ${API_ECR_URI}:latest -f Dockerfile .
docker push ${API_ECR_URI}:latest

docker build -t ${DASHBOARD_ECR_URI}:latest -f Dockerfile.dashboard .
docker push ${DASHBOARD_ECR_URI}:latest
```

#### Step 3: Configure Secrets

```bash
# Get the secrets ARN
API_SECRETS_ARN=$(aws cloudformation describe-stacks \
  --stack-name khepra-protocol-infrastructure \
  --query "Stacks[0].Outputs[?OutputKey=='APISecretsArn'].OutputValue" \
  --output text --region us-gov-west-1)

# Update with your actual values
aws secretsmanager update-secret \
  --secret-id ${API_SECRETS_ARN} \
  --secret-string '{
    "SUPABASE_URL": "https://your-project.supabase.co",
    "SUPABASE_ANON_KEY": "your-anon-key",
    "OPENAI_API_KEY": "sk-...",
    "XAI_API_KEY": "xai-...",
    "STRIPE_SECRET_KEY": "sk_live_..."
  }' \
  --region us-gov-west-1
```

#### Step 4: Deploy ECS Services

```bash
aws cloudformation deploy \
  --stack-name khepra-protocol-services \
  --template-file aws-govcloud/cloudformation/khepra-ecs-services.yaml \
  --parameter-overrides \
    ProjectName=khepra-protocol \
    Environment=production \
    APIImageTag=latest \
    DashboardImageTag=latest \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-gov-west-1
```

## Configuration Options

### Infrastructure Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ProjectName` | khepra-protocol | Project identifier (lowercase) |
| `Environment` | production | Environment (development/staging/production) |
| `VPCCidr` | 10.0.0.0/16 | VPC CIDR block |
| `EnableFlowLogs` | true | Enable VPC Flow Logs for compliance |
| `EnableFIPS` | true | Enable FIPS 140-2 endpoints |
| `AllowedCIDR` | 0.0.0.0/0 | CIDR allowed to access ALB |

### ECS Service Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `APIDesiredCount` | 2 | Number of API task instances |
| `DashboardDesiredCount` | 2 | Number of Dashboard task instances |
| `APIImageTag` | latest | Docker image tag for API |
| `DashboardImageTag` | latest | Docker image tag for Dashboard |

## Compliance Features

### FedRAMP High Controls

- **VPC Flow Logs**: All network traffic logged to CloudWatch
- **KMS Encryption**: All data encrypted at rest with customer-managed keys
- **ECR Image Scanning**: Automatic vulnerability scanning on push
- **Private Subnets**: ECS tasks run in private subnets with NAT
- **Security Groups**: Least-privilege network access
- **IAM Roles**: Task-specific roles with minimal permissions
- **Container Insights**: Full observability with CloudWatch
- **SSDLC Aligned**: Developed following the [Secure Software Development Lifecycle](../docs/SECURE_DEVELOPMENT_LIFECYCLE.md) (AS02-AS06)

### IL4/IL5 Considerations

1. **Network Isolation**: Restrict `AllowedCIDR` to specific IP ranges
2. **No Internet Egress**: Modify NAT gateway for air-gapped deployments
3. **FIPS Endpoints**: Enabled by default
4. **Data Classification**: All data stored in GovCloud region

## Post-Deployment Setup

### 1. Configure HTTPS

```bash
# Request certificate in ACM
aws acm request-certificate \
  --domain-name khepra.yourdomain.gov \
  --validation-method DNS \
  --region us-gov-west-1

# After validation, update ALB listener
# (See CloudFormation template for HTTPS listener configuration)
```

### 2. Configure Custom Domain

```bash
# Create Route 53 hosted zone (if needed)
aws route53 create-hosted-zone \
  --name khepra.yourdomain.gov \
  --caller-reference $(date +%s)

# Create alias record pointing to ALB
```

### 3. Update Supabase Configuration

Update your Supabase project settings:
- Add redirect URL: `https://khepra.yourdomain.gov/auth/callback`
- Update site URL to production domain

## Monitoring & Operations

### View Logs

```bash
# API logs
aws logs tail /ecs/khepra-protocol/api --follow --region us-gov-west-1

# Dashboard logs
aws logs tail /ecs/khepra-protocol/dashboard --follow --region us-gov-west-1

# VPC Flow Logs
aws logs tail /aws/vpc/khepra-protocol-flow-logs --follow --region us-gov-west-1
```

### ECS Exec (SSH into containers)

```bash
# Get task ID
TASK_ID=$(aws ecs list-tasks \
  --cluster khepra-protocol-production \
  --service-name khepra-protocol-api \
  --query 'taskArns[0]' --output text --region us-gov-west-1 | \
  cut -d'/' -f3)

# Connect to container
aws ecs execute-command \
  --cluster khepra-protocol-production \
  --task $TASK_ID \
  --container api \
  --interactive \
  --command /bin/sh \
  --region us-gov-west-1
```

### Scale Services

```bash
# Scale API service
aws ecs update-service \
  --cluster khepra-protocol-production \
  --service khepra-protocol-api \
  --desired-count 4 \
  --region us-gov-west-1
```

## Troubleshooting

### Common Issues

**1. ECS tasks failing to start**
- Check CloudWatch logs for container errors
- Verify secrets are properly configured
- Ensure ECR images exist and are accessible

**2. ALB health checks failing**
- Verify security group rules allow health check traffic
- Check container health check commands
- Review application startup logs

**3. Can't connect to database**
- Verify RDS security group allows ECS security group
- Check database credentials in Secrets Manager
- Ensure tasks are in correct subnets

### Get Support

- Check CloudWatch Container Insights for metrics
- Review CloudTrail for API activity
- Contact: support@souhimbou.org

## Cost Estimation

| Resource | Monthly Cost (approx) |
|----------|----------------------|
| ECS Fargate (4 tasks) | $150-200 |
| Application Load Balancer | $25-30 |
| NAT Gateway (2x) | $90-100 |
| CloudWatch Logs | $10-20 |
| KMS | $1-5 |
| **Total** | **~$280-360/month** |

*Note: Costs vary based on usage and region. Production with RDS will be higher.*

## Security Contacts

For security issues or vulnerability reports:
- Email: security@souhimbou.org
- PGP Key: [Available upon request]

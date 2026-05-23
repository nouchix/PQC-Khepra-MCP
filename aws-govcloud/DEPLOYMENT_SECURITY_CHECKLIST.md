# KHEPRA PROTOCOL - AWS GovCloud Deployment Security Checklist

## Compliance Framework Alignment Matrix

| Control Area | IronBank | NIST 800-171 | CMMC 3.0 | SOC-2 | ISO 27001 | FedRAMP High |
|--------------|----------|--------------|----------|-------|-----------|--------------|
| Access Control | STIG AC-* | 3.1.x | AC.L2-3.1.x | CC6.1 | A.9 | AC-2,3,6 |
| Audit Logging | STIG AU-* | 3.3.x | AU.L2-3.3.x | CC7.2 | A.12.4 | AU-2,3,6,12 |
| Cryptography | FIPS 140-2 | 3.13.x | SC.L2-3.13.x | CC6.7 | A.10 | SC-8,12,13 |
| Incident Response | - | 3.6.x | IR.L2-3.6.x | CC7.4 | A.16 | IR-4,6,8 |
| Identity Auth | MFA Required | 3.5.x | IA.L2-3.5.x | CC6.1 | A.9.2 | IA-2,5,8 |

---

## PRE-DEPLOYMENT CHECKLIST

### Phase 1: Credential Security (CRITICAL)

- [ ] **1.1** AWS GovCloud credentials stored in AWS Secrets Manager or HashiCorp Vault
- [ ] **1.2** NO credentials in source code, .env files, or environment variables
- [ ] **1.3** IAM user created with **minimum privilege** (see IAM policy below)
- [ ] **1.4** MFA enabled on ALL IAM users (CMMC IA.L2-3.5.3)
- [ ] **1.5** Access keys rotated every 90 days (NIST 800-171 3.5.10)
- [ ] **1.6** AWS CloudTrail enabled in ALL regions (NIST 800-171 3.3.1)
- [ ] **1.7** Session Manager preferred over SSH (no exposed ports)

### Phase 2: Network Security

- [ ] **2.1** VPC Flow Logs enabled (FedRAMP AU-12)
- [ ] **2.2** All traffic via private subnets (except ALB)
- [ ] **2.3** Security Groups follow least-privilege (only required ports)
- [ ] **2.4** No 0.0.0.0/0 ingress rules except HTTP/HTTPS on ALB
- [ ] **2.5** NAT Gateway for outbound traffic (no direct internet access for workloads)
- [ ] **2.6** VPC Endpoints for AWS services (S3, ECR, Secrets Manager, CloudWatch)
- [ ] **2.7** Network ACLs as secondary defense layer

### Phase 3: Data Protection

- [ ] **3.1** KMS Customer Managed Keys (CMK) for all encryption
- [ ] **3.2** S3 bucket encryption enabled (SSE-KMS)
- [ ] **3.3** RDS encryption at rest enabled
- [ ] **3.4** TLS 1.2+ enforced on all endpoints (FIPS 140-2 compliant)
- [ ] **3.5** EBS volumes encrypted
- [ ] **3.6** ECR image scanning enabled
- [ ] **3.7** Secrets Manager for all application secrets

### Phase 4: Container Security (Iron Bank)

- [ ] **4.1** Base images from registry1.dso.mil/ironbank only
- [ ] **4.2** No root user in containers (UID 1001+)
- [ ] **4.3** Read-only root filesystem where possible
- [ ] **4.4** No privileged containers
- [ ] **4.5** Resource limits defined (CPU/Memory)
- [ ] **4.6** Health checks configured
- [ ] **4.7** No exposed secrets in image layers
- [ ] **4.8** Container images signed with Cosign/Notary

### Phase 5: Audit & Logging (SOC-2 / NIST 3.3.x)

- [ ] **5.1** CloudWatch Logs enabled for all services
- [ ] **5.2** Log retention: 90 days minimum (365 for production)
- [ ] **5.3** CloudTrail with S3 bucket logging
- [ ] **5.4** GuardDuty enabled
- [ ] **5.5** Config Rules for compliance monitoring
- [ ] **5.6** Security Hub enabled
- [ ] **5.7** Log integrity validation (tamper-evident)

### Phase 6: Incident Response

- [ ] **6.1** SNS topics for security alerts
- [ ] **6.2** Lambda functions for automated response
- [ ] **6.3** Runbook documented for common incidents
- [ ] **6.4** Contact list for security team
- [ ] **6.5** Backup/restore procedures tested

---

## AWS GOVCLOUD CREDENTIAL SETUP PROCEDURE

### Step 1: Create IAM Policy (Least Privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KhepraDeploy",
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "ecs:*",
        "ecr:*",
        "ec2:Describe*",
        "ec2:CreateVpc",
        "ec2:CreateSubnet",
        "ec2:CreateSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:CreateInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:CreateNatGateway",
        "ec2:AllocateAddress",
        "ec2:CreateRouteTable",
        "ec2:CreateRoute",
        "ec2:AssociateRouteTable",
        "ec2:ModifyVpcAttribute",
        "elasticloadbalancing:*",
        "logs:*",
        "secretsmanager:*",
        "kms:CreateKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "iam:GetRole",
        "iam:CreateServiceLinkedRole",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["us-gov-west-1", "us-gov-east-1"]
        }
      }
    }
  ]
}
```

### Step 2: Configure AWS CLI Securely

```powershell
# Create dedicated profile for GovCloud
aws configure --profile khepra-govcloud

# Enter credentials when prompted:
# AWS Access Key ID: [from IAM]
# AWS Secret Access Key: [from IAM]
# Default region: us-gov-west-1
# Output format: json

# Verify configuration
aws sts get-caller-identity --profile khepra-govcloud
```

### Step 3: Enable MFA (REQUIRED)

```powershell
# Create virtual MFA device
aws iam create-virtual-mfa-device `
    --virtual-mfa-device-name khepra-deploy-mfa `
    --outfile mfa-qr.png `
    --bootstrap-method QRCodePNG

# After scanning QR code in authenticator app:
aws iam enable-mfa-device `
    --user-name khepra-deploy-user `
    --serial-number arn:aws-us-gov:iam::ACCOUNT_ID:mfa/khepra-deploy-mfa `
    --authentication-code1 CODE1 `
    --authentication-code2 CODE2
```

### Step 4: Configure Credential Rotation

```powershell
# Set up automatic key rotation (every 90 days)
# Add to Windows Task Scheduler or cron:

# rotate-keys.ps1
$OldKey = aws iam list-access-keys --user-name khepra-deploy-user --query 'AccessKeyMetadata[0].AccessKeyId' --output text
$NewKey = aws iam create-access-key --user-name khepra-deploy-user
# Update local configuration
# Delete old key after 24 hours
aws iam delete-access-key --user-name khepra-deploy-user --access-key-id $OldKey
```

---

## SECRETS MANAGEMENT ARCHITECTURE

```
+------------------------+     +---------------------------+
|   Local Development    |     |    AWS GovCloud Prod      |
+------------------------+     +---------------------------+
|                        |     |                           |
| .env.local (gitignored)|     | AWS Secrets Manager       |
| - Local test values    |     | - Encrypted with KMS CMK  |
| - Never committed      |     | - Auto-rotation enabled   |
|                        |     | - Audit trail in CloudTrail
+------------------------+     +---------------------------+
         |                              |
         v                              v
+----------------------------------------------------------+
|                    APPLICATION                            |
|  - Never hardcode secrets                                 |
|  - Use AWS SDK to retrieve at runtime                     |
|  - Cache with TTL (5 min max)                            |
+----------------------------------------------------------+
```

### Required Secrets in Secrets Manager:

| Secret Name | Description | Rotation |
|------------|-------------|----------|
| khepra/api/supabase | Supabase URL + Anon Key | 90 days |
| khepra/api/openai | OpenAI API Key | 90 days |
| khepra/api/xai | xAI API Key | 90 days |
| khepra/api/stripe | Stripe Secret Key | 90 days |
| khepra/pqc/master-key | ML-DSA-65 Master Private Key | 365 days |
| khepra/pqc/license-key | License signing key | 365 days |

---

## DEPLOYMENT EXECUTION

### Pre-Flight Checks

```powershell
# 1. Verify identity
aws sts get-caller-identity --profile khepra-govcloud

# 2. Verify MFA session (if required)
aws sts get-session-token --serial-number arn:aws-us-gov:iam::ACCOUNT:mfa/NAME --token-code CODE

# 3. Check for existing resources
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --profile khepra-govcloud

# 4. Validate templates
aws cloudformation validate-template --template-body file://cloudformation/khepra-govcloud-infrastructure.yaml
```

### Deploy Command

```powershell
# Set environment variables (DO NOT hardcode in script)
$env:AWS_PROFILE = "khepra-govcloud"
$env:AWS_DEFAULT_REGION = "us-gov-west-1"

# Execute deployment
.\aws-govcloud\scripts\deploy-govcloud.ps1 -Environment production -Region us-gov-west-1
```

---

## POST-DEPLOYMENT VERIFICATION

### Security Validation Checklist

```powershell
# 1. Verify VPC Flow Logs
aws ec2 describe-flow-logs --filter "Name=resource-id,Values=vpc-XXXXX"

# 2. Verify encryption
aws kms list-keys --query 'Keys[*].KeyId'
aws kms describe-key --key-id KEY_ID

# 3. Verify CloudTrail
aws cloudtrail describe-trails

# 4. Verify GuardDuty
aws guardduty list-detectors

# 5. Verify Security Groups (no 0.0.0.0/0 except ALB)
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'

# 6. Verify container security
aws ecs describe-task-definition --task-definition khepra-api --query 'taskDefinition.containerDefinitions[*].{user:user,privileged:privileged}'
```

---

## COMPLIANCE EVIDENCE GENERATION

### For CMMC Assessment

```powershell
# Generate POA&M evidence package
.\bin\adinkhepra.exe compliance export --format cmmc --level 3 --output cmmc-evidence.zip
```

### For FedRAMP Audit

```powershell
# Generate SSP supporting documentation
.\bin\adinkhepra.exe compliance export --format fedramp --baseline high --output ssp-attachments.zip
```

### For SOC-2 Type II

```powershell
# Generate control evidence
.\bin\adinkhepra.exe compliance audit-log --start 2024-01-01 --end 2024-12-31 --output soc2-evidence/
```

---

## EMERGENCY PROCEDURES

### Credential Compromise Response

1. **IMMEDIATE**: Disable compromised access key
   ```powershell
   aws iam update-access-key --access-key-id COMPROMISED_KEY --status Inactive --user-name USER
   ```

2. **WITHIN 1 HOUR**:
   - Rotate all secrets in Secrets Manager
   - Review CloudTrail for unauthorized access
   - Enable additional GuardDuty findings

3. **WITHIN 24 HOURS**:
   - Full security audit
   - Incident report to security team
   - Update all dependent systems

### Service Disruption Response

1. **CHECK**: ECS service health
   ```powershell
   aws ecs describe-services --cluster khepra-cluster --services khepra-api khepra-dashboard
   ```

2. **ROLLBACK**: If needed
   ```powershell
   aws ecs update-service --cluster khepra-cluster --service khepra-api --task-definition khepra-api:PREVIOUS_VERSION
   ```

---

## ATTESTATION

By deploying this system, you attest that:

1. All credentials are stored securely (not in source code)
2. MFA is enabled on all administrative accounts
3. Audit logging is enabled and monitored
4. The deployment follows NIST 800-171/172 controls
5. CMMC Level 3 practices are implemented

**Deployment Authorized By**: ________________________
**Date**: ________________________
**Security Review Completed**: [ ] Yes [ ] No

---

*Document Version: 1.0*
*Last Updated: 2026-01-27*
*Classification: CUI // NOFORN*

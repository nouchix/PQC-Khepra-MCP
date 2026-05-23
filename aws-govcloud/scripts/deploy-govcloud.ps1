# =============================================================================
# KHEPRA PROTOCOL - AWS GOVCLOUD DEPLOYMENT SCRIPT (PowerShell)
# =============================================================================
# Deploys the full Khepra Protocol stack to AWS GovCloud
#
# Prerequisites:
#   - AWS CLI v2 configured with GovCloud credentials
#   - Docker Desktop installed and running
#
# Usage:
#   .\deploy-govcloud.ps1 [-Environment production] [-Region us-gov-west-1]
# =============================================================================

param(
    [string]$Environment = "production",
    [string]$Region = "us-gov-west-1"
)

$ErrorActionPreference = "Stop"

# Configuration
$ProjectName = "khepra-protocol"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = (Get-Item "$ScriptDir\..\..").FullName
$CfnDir = "$ScriptDir\..\cloudformation"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KHEPRA PROTOCOL - AWS GOVCLOUD DEPLOYMENT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Project:     $ProjectName"
Write-Host "  Environment: $Environment"
Write-Host "  Region:      $Region"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan

# =============================================================================
# STEP 1: Verify Prerequisites
# =============================================================================
Write-Host "[INFO] Step 1/6: Verifying prerequisites..." -ForegroundColor Yellow

# Check AWS CLI
try {
    $null = Get-Command aws -ErrorAction Stop
} catch {
    Write-Host "[ERROR] AWS CLI not installed" -ForegroundColor Red
    exit 1
}

# Check Docker
try {
    $null = Get-Command docker -ErrorAction Stop
} catch {
    Write-Host "[ERROR] Docker not installed" -ForegroundColor Red
    exit 1
}

# Verify AWS credentials
try {
    $AwsAccountId = aws sts get-caller-identity --query Account --output text --region $Region
    Write-Host "[SUCCESS] AWS Account: $AwsAccountId" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] AWS credentials not configured or invalid" -ForegroundColor Red
    exit 1
}

# Check if GovCloud
if ($Region -like "us-gov-*") {
    Write-Host "[SUCCESS] GovCloud region detected: $Region" -ForegroundColor Green
    $AwsPartition = "aws-us-gov"
} else {
    Write-Host "[WARN] Not a GovCloud region. Proceeding with commercial AWS." -ForegroundColor Yellow
    $AwsPartition = "aws"
}

# =============================================================================
# STEP 2: Deploy Infrastructure Stack
# =============================================================================
Write-Host ""
Write-Host "[INFO] Step 2/6: Deploying infrastructure stack..." -ForegroundColor Yellow

$InfraStackName = "$ProjectName-infrastructure"

aws cloudformation deploy `
    --stack-name $InfraStackName `
    --template-file "$CfnDir\khepra-govcloud-infrastructure.yaml" `
    --parameter-overrides `
        ProjectName=$ProjectName `
        Environment=$Environment `
        EnableFlowLogs=true `
        EnableFIPS=true `
    --capabilities CAPABILITY_NAMED_IAM `
    --region $Region `
    --tags `
        Project=$ProjectName `
        Environment=$Environment `
        Compliance=FedRAMP-High

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Infrastructure stack deployment failed" -ForegroundColor Red
    exit 1
}

Write-Host "[SUCCESS] Infrastructure stack deployed successfully" -ForegroundColor Green

# Get stack outputs
$ApiEcrUri = aws cloudformation describe-stacks `
    --stack-name $InfraStackName `
    --query "Stacks[0].Outputs[?OutputKey=='APIRepositoryUri'].OutputValue" `
    --output text --region $Region

$DashboardEcrUri = aws cloudformation describe-stacks `
    --stack-name $InfraStackName `
    --query "Stacks[0].Outputs[?OutputKey=='DashboardRepositoryUri'].OutputValue" `
    --output text --region $Region

$AlbDns = aws cloudformation describe-stacks `
    --stack-name $InfraStackName `
    --query "Stacks[0].Outputs[?OutputKey=='ALBDNSName'].OutputValue" `
    --output text --region $Region

# =============================================================================
# STEP 3: Build and Push Docker Images
# =============================================================================
Write-Host ""
Write-Host "[INFO] Step 3/6: Building and pushing Docker images..." -ForegroundColor Yellow

# Login to ECR
$EcrPassword = aws ecr get-login-password --region $Region
$EcrPassword | docker login --username AWS --password-stdin "$AwsAccountId.dkr.ecr.$Region.amazonaws.com"

# Build and push API image
Write-Host "[INFO] Building API image..." -ForegroundColor Yellow
docker build -t "${ApiEcrUri}:latest" -f "$RootDir\Dockerfile" $RootDir
docker push "${ApiEcrUri}:latest"
Write-Host "[SUCCESS] API image pushed to ECR" -ForegroundColor Green

# Build and push Dashboard image
Write-Host "[INFO] Building Dashboard image..." -ForegroundColor Yellow
docker build -t "${DashboardEcrUri}:latest" -f "$RootDir\Dockerfile.dashboard" $RootDir
docker push "${DashboardEcrUri}:latest"
Write-Host "[SUCCESS] Dashboard image pushed to ECR" -ForegroundColor Green

# =============================================================================
# STEP 4: Update Secrets (if needed)
# =============================================================================
Write-Host ""
Write-Host "[INFO] Step 4/6: Checking secrets configuration..." -ForegroundColor Yellow

$ApiSecretsArn = aws cloudformation describe-stacks `
    --stack-name $InfraStackName `
    --query "Stacks[0].Outputs[?OutputKey=='APISecretsArn'].OutputValue" `
    --output text --region $Region

try {
    $CurrentSecrets = aws secretsmanager get-secret-value `
        --secret-id $ApiSecretsArn `
        --query SecretString --output text --region $Region

    if ($CurrentSecrets -match "REPLACE_ME") {
        Write-Host "[WARN] Secrets contain placeholder values. Please update them:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  aws secretsmanager update-secret ``"
        Write-Host "    --secret-id $ApiSecretsArn ``"
        Write-Host "    --secret-string '{`"SUPABASE_URL`":`"...`",`"SUPABASE_ANON_KEY`":`"...`",`"OPENAI_API_KEY`":`"...`",`"XAI_API_KEY`":`"...`",`"STRIPE_SECRET_KEY`":`"...`"}' ``"
        Write-Host "    --region $Region"
        Write-Host ""
        Read-Host "Press Enter after updating secrets, or Ctrl+C to abort"
    }
} catch {
    Write-Host "[WARN] Could not retrieve secrets. They may need to be configured." -ForegroundColor Yellow
}

# =============================================================================
# STEP 5: Deploy ECS Services Stack
# =============================================================================
Write-Host ""
Write-Host "[INFO] Step 5/6: Deploying ECS services stack..." -ForegroundColor Yellow

$ServicesStackName = "$ProjectName-services"

aws cloudformation deploy `
    --stack-name $ServicesStackName `
    --template-file "$CfnDir\khepra-ecs-services.yaml" `
    --parameter-overrides `
        ProjectName=$ProjectName `
        Environment=$Environment `
        APIImageTag=latest `
        DashboardImageTag=latest `
        APIDesiredCount=2 `
        DashboardDesiredCount=2 `
    --capabilities CAPABILITY_NAMED_IAM `
    --region $Region `
    --tags `
        Project=$ProjectName `
        Environment=$Environment

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Services stack deployment failed" -ForegroundColor Red
    exit 1
}

Write-Host "[SUCCESS] Services stack deployed successfully" -ForegroundColor Green

# =============================================================================
# STEP 6: Verify Deployment
# =============================================================================
Write-Host ""
Write-Host "[INFO] Step 6/6: Verifying deployment..." -ForegroundColor Yellow

$EcsCluster = aws cloudformation describe-stacks `
    --stack-name $InfraStackName `
    --query "Stacks[0].Outputs[?OutputKey=='ECSClusterName'].OutputValue" `
    --output text --region $Region

Write-Host "[INFO] Waiting for ECS services to stabilize..." -ForegroundColor Yellow

aws ecs wait services-stable `
    --cluster $EcsCluster `
    --services "$ProjectName-api" "$ProjectName-dashboard" `
    --region $Region

$ApiRunning = aws ecs describe-services `
    --cluster $EcsCluster `
    --services "$ProjectName-api" `
    --query "services[0].runningCount" `
    --output text --region $Region

$DashboardRunning = aws ecs describe-services `
    --cluster $EcsCluster `
    --services "$ProjectName-dashboard" `
    --query "services[0].runningCount" `
    --output text --region $Region

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Application URL: http://$AlbDns" -ForegroundColor Cyan
Write-Host "  API Endpoint:    http://$AlbDns/api/" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Running Tasks:"
Write-Host "    - API:       $ApiRunning task(s)"
Write-Host "    - Dashboard: $DashboardRunning task(s)"
Write-Host ""
Write-Host "  Next Steps:" -ForegroundColor Yellow
Write-Host "    1. Configure HTTPS certificate in ACM"
Write-Host "    2. Update ALB listener to use HTTPS"
Write-Host "    3. Set up Route 53 DNS (if using custom domain)"
Write-Host "    4. Update Supabase redirect URLs"
Write-Host ""
Write-Host "  Useful Commands:" -ForegroundColor Yellow
Write-Host "    # View API logs"
Write-Host "    aws logs tail /ecs/$ProjectName/api --follow --region $Region"
Write-Host ""
Write-Host "    # View Dashboard logs"
Write-Host "    aws logs tail /ecs/$ProjectName/dashboard --follow --region $Region"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green

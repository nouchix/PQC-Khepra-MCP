#!/bin/bash
# =============================================================================
# KHEPRA PROTOCOL - AWS GOVCLOUD DEPLOYMENT SCRIPT
# =============================================================================
# Deploys the full Khepra Protocol stack to AWS GovCloud
#
# Prerequisites:
#   - AWS CLI v2 configured with GovCloud credentials
#   - Docker installed and running
#   - jq installed (for JSON parsing)
#
# Usage:
#   ./deploy-govcloud.sh [environment] [region]
#   ./deploy-govcloud.sh production us-gov-west-1
# =============================================================================

set -euo pipefail

# Configuration
PROJECT_NAME="khepra-protocol"
ENVIRONMENT="${1:-production}"
AWS_REGION="${2:-us-gov-west-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CFN_DIR="${SCRIPT_DIR}/../cloudformation"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo "============================================================"
echo "  KHEPRA PROTOCOL - AWS GOVCLOUD DEPLOYMENT"
echo "============================================================"
echo ""
echo "  Project:     ${PROJECT_NAME}"
echo "  Environment: ${ENVIRONMENT}"
echo "  Region:      ${AWS_REGION}"
echo ""
echo "============================================================"

# =============================================================================
# STEP 1: Verify Prerequisites
# =============================================================================
log_info "Step 1/6: Verifying prerequisites..."

command -v aws >/dev/null 2>&1 || log_error "AWS CLI not installed"
command -v docker >/dev/null 2>&1 || log_error "Docker not installed"
command -v jq >/dev/null 2>&1 || log_error "jq not installed"

# Verify AWS credentials
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --region ${AWS_REGION} 2>/dev/null) || log_error "AWS credentials not configured or invalid"
log_success "AWS Account: ${AWS_ACCOUNT_ID}"

# Check if GovCloud
if [[ "${AWS_REGION}" == us-gov-* ]]; then
    log_success "GovCloud region detected: ${AWS_REGION}"
    AWS_PARTITION="aws-us-gov"
else
    log_warn "Not a GovCloud region. Proceeding with commercial AWS."
    AWS_PARTITION="aws"
fi

# =============================================================================
# STEP 2: Deploy Infrastructure Stack
# =============================================================================
log_info "Step 2/6: Deploying infrastructure stack..."

INFRA_STACK_NAME="${PROJECT_NAME}-infrastructure"

aws cloudformation deploy \
    --stack-name "${INFRA_STACK_NAME}" \
    --template-file "${CFN_DIR}/khepra-govcloud-infrastructure.yaml" \
    --parameter-overrides \
        ProjectName="${PROJECT_NAME}" \
        Environment="${ENVIRONMENT}" \
        EnableFlowLogs=true \
        EnableFIPS=true \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "${AWS_REGION}" \
    --tags \
        Project="${PROJECT_NAME}" \
        Environment="${ENVIRONMENT}" \
        Compliance="FedRAMP-High" \
    || log_error "Infrastructure stack deployment failed"

log_success "Infrastructure stack deployed successfully"

# Get stack outputs
API_ECR_URI=$(aws cloudformation describe-stacks \
    --stack-name "${INFRA_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='APIRepositoryUri'].OutputValue" \
    --output text --region "${AWS_REGION}")

DASHBOARD_ECR_URI=$(aws cloudformation describe-stacks \
    --stack-name "${INFRA_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='DashboardRepositoryUri'].OutputValue" \
    --output text --region "${AWS_REGION}")

ALB_DNS=$(aws cloudformation describe-stacks \
    --stack-name "${INFRA_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='ALBDNSName'].OutputValue" \
    --output text --region "${AWS_REGION}")

# =============================================================================
# STEP 3: Build and Push Docker Images
# =============================================================================
log_info "Step 3/6: Building and pushing Docker images..."

# Login to ECR
aws ecr get-login-password --region "${AWS_REGION}" | \
    docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Build and push API image
log_info "Building API image..."
docker build -t "${API_ECR_URI}:latest" -f "${ROOT_DIR}/Dockerfile" "${ROOT_DIR}"
docker push "${API_ECR_URI}:latest"
log_success "API image pushed to ECR"

# Build and push Dashboard image
log_info "Building Dashboard image..."
docker build -t "${DASHBOARD_ECR_URI}:latest" -f "${ROOT_DIR}/Dockerfile.dashboard" "${ROOT_DIR}"
docker push "${DASHBOARD_ECR_URI}:latest"
log_success "Dashboard image pushed to ECR"

# =============================================================================
# STEP 4: Update Secrets (if needed)
# =============================================================================
log_info "Step 4/6: Checking secrets configuration..."

API_SECRETS_ARN=$(aws cloudformation describe-stacks \
    --stack-name "${INFRA_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='APISecretsArn'].OutputValue" \
    --output text --region "${AWS_REGION}")

# Check if secrets need to be updated
CURRENT_SECRETS=$(aws secretsmanager get-secret-value \
    --secret-id "${API_SECRETS_ARN}" \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null || echo "{}")

if echo "${CURRENT_SECRETS}" | grep -q "REPLACE_ME"; then
    log_warn "Secrets contain placeholder values. Please update them:"
    echo ""
    echo "  aws secretsmanager update-secret \\"
    echo "    --secret-id ${API_SECRETS_ARN} \\"
    echo "    --secret-string '{\"SUPABASE_URL\":\"...\",\"SUPABASE_ANON_KEY\":\"...\",\"OPENAI_API_KEY\":\"...\",\"XAI_API_KEY\":\"...\",\"STRIPE_SECRET_KEY\":\"...\"}' \\"
    echo "    --region ${AWS_REGION}"
    echo ""
    read -p "Press Enter after updating secrets, or Ctrl+C to abort..."
fi

# =============================================================================
# STEP 5: Deploy ECS Services Stack
# =============================================================================
log_info "Step 5/6: Deploying ECS services stack..."

SERVICES_STACK_NAME="${PROJECT_NAME}-services"

aws cloudformation deploy \
    --stack-name "${SERVICES_STACK_NAME}" \
    --template-file "${CFN_DIR}/khepra-ecs-services.yaml" \
    --parameter-overrides \
        ProjectName="${PROJECT_NAME}" \
        Environment="${ENVIRONMENT}" \
        APIImageTag=latest \
        DashboardImageTag=latest \
        APIDesiredCount=2 \
        DashboardDesiredCount=2 \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "${AWS_REGION}" \
    --tags \
        Project="${PROJECT_NAME}" \
        Environment="${ENVIRONMENT}" \
    || log_error "Services stack deployment failed"

log_success "Services stack deployed successfully"

# =============================================================================
# STEP 6: Verify Deployment
# =============================================================================
log_info "Step 6/6: Verifying deployment..."

# Wait for services to stabilize
log_info "Waiting for ECS services to stabilize (this may take a few minutes)..."

ECS_CLUSTER=$(aws cloudformation describe-stacks \
    --stack-name "${INFRA_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='ECSClusterName'].OutputValue" \
    --output text --region "${AWS_REGION}")

aws ecs wait services-stable \
    --cluster "${ECS_CLUSTER}" \
    --services "${PROJECT_NAME}-api" "${PROJECT_NAME}-dashboard" \
    --region "${AWS_REGION}" || log_warn "Services may not be fully stable yet"

# Check service health
API_RUNNING=$(aws ecs describe-services \
    --cluster "${ECS_CLUSTER}" \
    --services "${PROJECT_NAME}-api" \
    --query "services[0].runningCount" \
    --output text --region "${AWS_REGION}")

DASHBOARD_RUNNING=$(aws ecs describe-services \
    --cluster "${ECS_CLUSTER}" \
    --services "${PROJECT_NAME}-dashboard" \
    --query "services[0].runningCount" \
    --output text --region "${AWS_REGION}")

echo ""
echo "============================================================"
echo "  DEPLOYMENT COMPLETE!"
echo "============================================================"
echo ""
echo "  Application URL: http://${ALB_DNS}"
echo "  API Endpoint:    http://${ALB_DNS}/api/"
echo ""
echo "  Running Tasks:"
echo "    - API:       ${API_RUNNING} task(s)"
echo "    - Dashboard: ${DASHBOARD_RUNNING} task(s)"
echo ""
echo "  Next Steps:"
echo "    1. Configure HTTPS certificate in ACM"
echo "    2. Update ALB listener to use HTTPS"
echo "    3. Set up Route 53 DNS (if using custom domain)"
echo "    4. Update Supabase redirect URLs"
echo ""
echo "  Useful Commands:"
echo "    # View API logs"
echo "    aws logs tail /ecs/${PROJECT_NAME}/api --follow --region ${AWS_REGION}"
echo ""
echo "    # View Dashboard logs"
echo "    aws logs tail /ecs/${PROJECT_NAME}/dashboard --follow --region ${AWS_REGION}"
echo ""
echo "    # SSH into API container (ECS Exec)"
echo "    aws ecs execute-command --cluster ${ECS_CLUSTER} \\"
echo "      --task <task-id> --container api --interactive \\"
echo "      --command /bin/sh --region ${AWS_REGION}"
echo ""
echo "============================================================"

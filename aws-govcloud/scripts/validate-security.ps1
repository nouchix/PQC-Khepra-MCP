# =============================================================================
# KHEPRA PROTOCOL - AWS GovCloud Security Validation Script
# =============================================================================
# Validates deployment against IronBank, NIST 800-171, CMMC 3.0, SOC-2
# =============================================================================

param(
    [string]$Region = "us-gov-west-1",
    [string]$Profile = "khepra-govcloud",
    [switch]$Remediate,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$WarningCount = 0
$FailureCount = 0
$PassCount = 0

function Write-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Compliance,
        [string]$Details = ""
    )

    $icon = switch ($Status) {
        "PASS" { "[PASS]"; $script:PassCount++ }
        "FAIL" { "[FAIL]"; $script:FailureCount++ }
        "WARN" { "[WARN]"; $script:WarningCount++ }
        default { "[INFO]" }
    }

    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Cyan" }
    }

    Write-Host "$icon " -ForegroundColor $color -NoNewline
    Write-Host "$Name " -NoNewline
    Write-Host "($Compliance)" -ForegroundColor DarkGray
    if ($Details -and $Verbose) {
        Write-Host "      $Details" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KHEPRA PROTOCOL - SECURITY VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Region:  $Region"
Write-Host "  Profile: $Profile"
Write-Host "  Date:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Set AWS profile
$env:AWS_PROFILE = $Profile
$env:AWS_DEFAULT_REGION = $Region

# =============================================================================
# PHASE 1: IDENTITY & ACCESS MANAGEMENT (NIST 800-171 3.1.x, 3.5.x)
# =============================================================================

Write-Host "`n[PHASE 1] IDENTITY & ACCESS MANAGEMENT" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 1.1: MFA on root account
try {
    $rootMfa = aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>$null
    if ($rootMfa -eq "1") {
        Write-Check -Name "Root account MFA enabled" -Status "PASS" -Compliance "NIST 3.5.3"
    } else {
        Write-Check -Name "Root account MFA enabled" -Status "FAIL" -Compliance "NIST 3.5.3"
    }
} catch {
    Write-Check -Name "Root account MFA enabled" -Status "WARN" -Compliance "NIST 3.5.3" -Details "Could not verify"
}

# Check 1.2: No IAM users without MFA
try {
    $usersNoMfa = aws iam generate-credential-report 2>$null
    Start-Sleep -Seconds 2
    $report = aws iam get-credential-report --query 'Content' --output text 2>$null
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($report))
    $noMfaCount = ($decoded -split "`n" | Select-Object -Skip 1 | Where-Object { $_ -match ",false," -and $_ -match "true," }).Count

    if ($noMfaCount -eq 0) {
        Write-Check -Name "All console users have MFA" -Status "PASS" -Compliance "CMMC IA.L2-3.5.3"
    } else {
        Write-Check -Name "All console users have MFA" -Status "FAIL" -Compliance "CMMC IA.L2-3.5.3" -Details "$noMfaCount users without MFA"
    }
} catch {
    Write-Check -Name "All console users have MFA" -Status "WARN" -Compliance "CMMC IA.L2-3.5.3"
}

# Check 1.3: Password policy
try {
    $policy = aws iam get-account-password-policy 2>$null | ConvertFrom-Json
    $policyOk = $policy.PasswordPolicy.MinimumPasswordLength -ge 14 -and
                $policy.PasswordPolicy.RequireSymbols -eq $true -and
                $policy.PasswordPolicy.RequireNumbers -eq $true -and
                $policy.PasswordPolicy.RequireUppercaseCharacters -eq $true -and
                $policy.PasswordPolicy.RequireLowercaseCharacters -eq $true

    if ($policyOk) {
        Write-Check -Name "Strong password policy configured" -Status "PASS" -Compliance "NIST 3.5.7"
    } else {
        Write-Check -Name "Strong password policy configured" -Status "FAIL" -Compliance "NIST 3.5.7"
    }
} catch {
    Write-Check -Name "Strong password policy configured" -Status "WARN" -Compliance "NIST 3.5.7"
}

# Check 1.4: Access keys age
try {
    $oldKeys = aws iam list-users --query 'Users[*].UserName' --output text 2>$null
    $oldKeyCount = 0
    foreach ($user in ($oldKeys -split '\t')) {
        if ($user) {
            $keys = aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[?Status==`Active`].CreateDate' --output text 2>$null
            foreach ($keyDate in ($keys -split '\t')) {
                if ($keyDate) {
                    $age = (Get-Date) - [DateTime]::Parse($keyDate)
                    if ($age.Days -gt 90) { $oldKeyCount++ }
                }
            }
        }
    }

    if ($oldKeyCount -eq 0) {
        Write-Check -Name "Access keys rotated within 90 days" -Status "PASS" -Compliance "NIST 3.5.10"
    } else {
        Write-Check -Name "Access keys rotated within 90 days" -Status "FAIL" -Compliance "NIST 3.5.10" -Details "$oldKeyCount old keys"
    }
} catch {
    Write-Check -Name "Access keys rotated within 90 days" -Status "WARN" -Compliance "NIST 3.5.10"
}

# =============================================================================
# PHASE 2: AUDIT & ACCOUNTABILITY (NIST 800-171 3.3.x)
# =============================================================================

Write-Host "`n[PHASE 2] AUDIT & ACCOUNTABILITY" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 2.1: CloudTrail enabled
try {
    $trails = aws cloudtrail describe-trails --query 'trailList[*].Name' --output text 2>$null
    if ($trails) {
        Write-Check -Name "CloudTrail enabled" -Status "PASS" -Compliance "NIST 3.3.1"
    } else {
        Write-Check -Name "CloudTrail enabled" -Status "FAIL" -Compliance "NIST 3.3.1"
    }
} catch {
    Write-Check -Name "CloudTrail enabled" -Status "WARN" -Compliance "NIST 3.3.1"
}

# Check 2.2: CloudTrail log validation
try {
    $validation = aws cloudtrail describe-trails --query 'trailList[?LogFileValidationEnabled==`true`].Name' --output text 2>$null
    if ($validation) {
        Write-Check -Name "CloudTrail log file validation" -Status "PASS" -Compliance "NIST 3.3.2"
    } else {
        Write-Check -Name "CloudTrail log file validation" -Status "FAIL" -Compliance "NIST 3.3.2"
    }
} catch {
    Write-Check -Name "CloudTrail log file validation" -Status "WARN" -Compliance "NIST 3.3.2"
}

# Check 2.3: GuardDuty enabled
try {
    $detectors = aws guardduty list-detectors --query 'DetectorIds' --output text 2>$null
    if ($detectors) {
        Write-Check -Name "GuardDuty enabled" -Status "PASS" -Compliance "NIST 3.14.6"
    } else {
        Write-Check -Name "GuardDuty enabled" -Status "FAIL" -Compliance "NIST 3.14.6"
    }
} catch {
    Write-Check -Name "GuardDuty enabled" -Status "WARN" -Compliance "NIST 3.14.6"
}

# Check 2.4: Security Hub enabled
try {
    $hub = aws securityhub describe-hub 2>$null
    if ($hub) {
        Write-Check -Name "Security Hub enabled" -Status "PASS" -Compliance "SOC-2 CC7.2"
    } else {
        Write-Check -Name "Security Hub enabled" -Status "FAIL" -Compliance "SOC-2 CC7.2"
    }
} catch {
    Write-Check -Name "Security Hub enabled" -Status "WARN" -Compliance "SOC-2 CC7.2"
}

# =============================================================================
# PHASE 3: NETWORK SECURITY (NIST 800-171 3.13.x)
# =============================================================================

Write-Host "`n[PHASE 3] NETWORK SECURITY" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 3.1: VPC Flow Logs
try {
    $flowLogs = aws ec2 describe-flow-logs --query 'FlowLogs[*].FlowLogId' --output text 2>$null
    if ($flowLogs) {
        Write-Check -Name "VPC Flow Logs enabled" -Status "PASS" -Compliance "FedRAMP AU-12"
    } else {
        Write-Check -Name "VPC Flow Logs enabled" -Status "FAIL" -Compliance "FedRAMP AU-12"
    }
} catch {
    Write-Check -Name "VPC Flow Logs enabled" -Status "WARN" -Compliance "FedRAMP AU-12"
}

# Check 3.2: No unrestricted security groups
try {
    $openSgs = aws ec2 describe-security-groups `
        --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0'] && (FromPort==null || FromPort==0 || FromPort==22 || FromPort==3389)]].GroupId" `
        --output text 2>$null

    if (-not $openSgs) {
        Write-Check -Name "No unrestricted SSH/RDP access" -Status "PASS" -Compliance "NIST 3.13.1"
    } else {
        Write-Check -Name "No unrestricted SSH/RDP access" -Status "FAIL" -Compliance "NIST 3.13.1" -Details "Open SGs: $openSgs"
    }
} catch {
    Write-Check -Name "No unrestricted SSH/RDP access" -Status "WARN" -Compliance "NIST 3.13.1"
}

# Check 3.3: Default VPC deleted
try {
    $defaultVpc = aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[*].VpcId' --output text 2>$null
    if (-not $defaultVpc) {
        Write-Check -Name "Default VPC deleted" -Status "PASS" -Compliance "CIS 2.1"
    } else {
        Write-Check -Name "Default VPC deleted" -Status "WARN" -Compliance "CIS 2.1" -Details "Default VPC exists"
    }
} catch {
    Write-Check -Name "Default VPC deleted" -Status "WARN" -Compliance "CIS 2.1"
}

# =============================================================================
# PHASE 4: DATA PROTECTION (NIST 800-171 3.13.x)
# =============================================================================

Write-Host "`n[PHASE 4] DATA PROTECTION" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 4.1: S3 bucket encryption
try {
    $buckets = aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>$null
    $unencrypted = 0
    foreach ($bucket in ($buckets -split '\t')) {
        if ($bucket) {
            try {
                $enc = aws s3api get-bucket-encryption --bucket $bucket 2>$null
                if (-not $enc) { $unencrypted++ }
            } catch {
                $unencrypted++
            }
        }
    }

    if ($unencrypted -eq 0) {
        Write-Check -Name "All S3 buckets encrypted" -Status "PASS" -Compliance "NIST 3.13.11"
    } else {
        Write-Check -Name "All S3 buckets encrypted" -Status "FAIL" -Compliance "NIST 3.13.11" -Details "$unencrypted unencrypted"
    }
} catch {
    Write-Check -Name "All S3 buckets encrypted" -Status "WARN" -Compliance "NIST 3.13.11"
}

# Check 4.2: S3 bucket public access blocked
try {
    $publicBlocked = aws s3control get-public-access-block --account-id (aws sts get-caller-identity --query 'Account' --output text) 2>$null
    if ($publicBlocked) {
        Write-Check -Name "S3 public access blocked (account)" -Status "PASS" -Compliance "NIST 3.13.5"
    } else {
        Write-Check -Name "S3 public access blocked (account)" -Status "FAIL" -Compliance "NIST 3.13.5"
    }
} catch {
    Write-Check -Name "S3 public access blocked (account)" -Status "WARN" -Compliance "NIST 3.13.5"
}

# Check 4.3: KMS key rotation
try {
    $keys = aws kms list-keys --query 'Keys[*].KeyId' --output text 2>$null
    $noRotation = 0
    foreach ($keyId in ($keys -split '\t')) {
        if ($keyId) {
            try {
                $rotation = aws kms get-key-rotation-status --key-id $keyId --query 'KeyRotationEnabled' --output text 2>$null
                if ($rotation -ne "True") { $noRotation++ }
            } catch {
                # Skip AWS managed keys
            }
        }
    }

    if ($noRotation -eq 0) {
        Write-Check -Name "KMS key rotation enabled" -Status "PASS" -Compliance "NIST 3.13.11"
    } else {
        Write-Check -Name "KMS key rotation enabled" -Status "WARN" -Compliance "NIST 3.13.11" -Details "$noRotation keys without rotation"
    }
} catch {
    Write-Check -Name "KMS key rotation enabled" -Status "WARN" -Compliance "NIST 3.13.11"
}

# =============================================================================
# PHASE 5: CONTAINER SECURITY (Iron Bank)
# =============================================================================

Write-Host "`n[PHASE 5] CONTAINER SECURITY (Iron Bank)" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 5.1: ECR image scanning
try {
    $repos = aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text 2>$null
    $noScan = 0
    foreach ($repo in ($repos -split '\t')) {
        if ($repo) {
            $scanConfig = aws ecr describe-repositories --repository-names $repo --query 'repositories[0].imageScanningConfiguration.scanOnPush' --output text 2>$null
            if ($scanConfig -ne "True") { $noScan++ }
        }
    }

    if ($noScan -eq 0) {
        Write-Check -Name "ECR image scanning enabled" -Status "PASS" -Compliance "Iron Bank"
    } else {
        Write-Check -Name "ECR image scanning enabled" -Status "FAIL" -Compliance "Iron Bank" -Details "$noScan repos without scanning"
    }
} catch {
    Write-Check -Name "ECR image scanning enabled" -Status "WARN" -Compliance "Iron Bank"
}

# Check 5.2: ECS tasks non-root
try {
    $taskDefs = aws ecs list-task-definitions --query 'taskDefinitionArns' --output text 2>$null
    $rootTasks = 0
    foreach ($taskArn in ($taskDefs -split '\t')) {
        if ($taskArn) {
            $user = aws ecs describe-task-definition --task-definition $taskArn --query 'taskDefinition.containerDefinitions[0].user' --output text 2>$null
            if (-not $user -or $user -eq "root" -or $user -eq "0") { $rootTasks++ }
        }
    }

    if ($rootTasks -eq 0) {
        Write-Check -Name "ECS tasks run as non-root" -Status "PASS" -Compliance "Iron Bank"
    } else {
        Write-Check -Name "ECS tasks run as non-root" -Status "WARN" -Compliance "Iron Bank" -Details "$rootTasks tasks as root"
    }
} catch {
    Write-Check -Name "ECS tasks run as non-root" -Status "WARN" -Compliance "Iron Bank"
}

# =============================================================================
# PHASE 6: SECRETS MANAGEMENT
# =============================================================================

Write-Host "`n[PHASE 6] SECRETS MANAGEMENT" -ForegroundColor Yellow
Write-Host "=" * 60

# Check 6.1: Secrets Manager used
try {
    $secrets = aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text 2>$null
    if ($secrets) {
        Write-Check -Name "Secrets Manager in use" -Status "PASS" -Compliance "NIST 3.13.10"
    } else {
        Write-Check -Name "Secrets Manager in use" -Status "WARN" -Compliance "NIST 3.13.10"
    }
} catch {
    Write-Check -Name "Secrets Manager in use" -Status "WARN" -Compliance "NIST 3.13.10"
}

# Check 6.2: No hardcoded credentials in task definitions
try {
    $taskDefs = aws ecs list-task-definitions --query 'taskDefinitionArns[-5:]' --output text 2>$null
    $hardcodedSecrets = 0
    foreach ($taskArn in ($taskDefs -split '\t')) {
        if ($taskArn) {
            $envVars = aws ecs describe-task-definition --task-definition $taskArn --query 'taskDefinition.containerDefinitions[*].environment[*].name' --output text 2>$null
            if ($envVars -match "PASSWORD|SECRET|API_KEY|TOKEN") {
                $hardcodedSecrets++
            }
        }
    }

    if ($hardcodedSecrets -eq 0) {
        Write-Check -Name "No hardcoded secrets in ECS" -Status "PASS" -Compliance "SOC-2 CC6.7"
    } else {
        Write-Check -Name "No hardcoded secrets in ECS" -Status "FAIL" -Compliance "SOC-2 CC6.7" -Details "$hardcodedSecrets tasks with potential secrets"
    }
} catch {
    Write-Check -Name "No hardcoded secrets in ECS" -Status "WARN" -Compliance "SOC-2 CC6.7"
}

# =============================================================================
# SUMMARY
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [PASS] $PassCount checks passed" -ForegroundColor Green
Write-Host "  [WARN] $WarningCount warnings" -ForegroundColor Yellow
Write-Host "  [FAIL] $FailureCount failures" -ForegroundColor Red
Write-Host ""

$totalChecks = $PassCount + $WarningCount + $FailureCount
$passRate = if ($totalChecks -gt 0) { [math]::Round(($PassCount / $totalChecks) * 100, 1) } else { 0 }

Write-Host "  Compliance Score: $passRate%" -ForegroundColor $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })
Write-Host ""

if ($FailureCount -gt 0) {
    Write-Host "  [!] DEPLOYMENT NOT RECOMMENDED - Fix failures first" -ForegroundColor Red
    exit 1
} elseif ($WarningCount -gt 3) {
    Write-Host "  [!] Review warnings before production deployment" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "  [OK] Infrastructure meets security requirements" -ForegroundColor Green
    exit 0
}

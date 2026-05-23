# scripts/retrieve_gov_keys.ps1
# Automates retrieval of AWS GovCloud Root Keys via AWS Secrets Manager & KMS
# Usage: .\scripts\retrieve_gov_keys.ps1
# Pre-requisite: Run 'aws configure' first with your Standard Account credentials.

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   AWS GovCloud Key Retrieval Tool" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 0. Check AWS CLI
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "AWS CLI is not installed or not in PATH."
    exit 1
}

# 1. Get the Encrypted Blob
$SecretID = "arn:aws:secretsmanager:us-east-1:536883072436:secret:VjgeDdMeVxbQxsn-eDBsWG"
Write-Host "`n[1/3] Fetching secret blob from Secrets Manager..."
Write-Host "      ID: $SecretID"
try {
    $Blob = aws secretsmanager get-secret-value --secret-id $SecretID --region us-east-1 --version-stage AWSCURRENT --query SecretString --output text
    if (-not $Blob) { throw "Empty blob returned" }
    Write-Host "      Status: Success" -ForegroundColor Green
} catch {
    Write-Error "Failed to fetch secret. Ensure you are logged into the standard AWS account (run 'aws configure')."
    Write-Error $_
    exit 1
}

# 2. Decrypt with KMS
$KmsKey = "arn:aws:kms:us-east-1:445971788114:key/5abd3245-a5ef-482e-8697-3dd8a7dc0f38"
Write-Host "`n[2/3] Decrypting blob with KMS..."
Write-Host "      Key: $KmsKey"
try {
    # aws kms decrypt accepts base64 stirng for --ciphertext-blob
    $PayloadBase64 = aws kms decrypt --region us-east-1 --key-id $KmsKey --encryption-algorithm RSAES_OAEP_SHA_256 --ciphertext-blob $Blob --query Plaintext --output text
    if (-not $PayloadBase64) { throw "Empty payload returned" }
    Write-Host "      Status: Success" -ForegroundColor Green
} catch {
    Write-Error "Failed to decrypt blob. You might not have permission to decrypt with this key."
    Write-Error $_
    exit 1
}

# 3. Decode the final JSON
Write-Host "`n[3/3] Decoding final keys..."
try {
    $KeysJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($PayloadBase64))
    
    Write-Host "`nSUCCESS! Here are your AWS GovCloud Root Keys:" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host $KeysJson -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host "`nACTION REQUIRED: Save these keys immediately to a secure location (e.g., password manager)." -ForegroundColor Red
} catch {
    Write-Error "Failed to decode final JSON."
    Write-Error $_
    exit 1
}

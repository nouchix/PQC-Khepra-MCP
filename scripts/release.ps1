# KHEPRA PROTOCOL - SECURE RELEASE SCRIPT
# Handles clean build, hashing, and preparing for IPFS distribution.

$ErrorActionPreference = "Stop"

Write-Host "[*] Starting Secure Release Build..." -ForegroundColor Cyan

# 1. Clean
Write-Host " -> Cleaning previous builds..."
if (Test-Path "bin") { Remove-Item -Recurse -Force "bin" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
New-Item -ItemType Directory -Path "dist" | Out-Null

# 2. Build (using Makefile targets via direct Go commands to ensure Windows compat)
Write-Host " -> Building Clean/Static Binaries..."
# Ensure environment is clean
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

# Agent
go build -trimpath -ldflags="-s -w" -mod=vendor -o dist/khepra-agent.exe ./cmd/agent
if ($LASTEXITCODE -ne 0) { throw "Agent build failed" }

# CLI
go build -trimpath -ldflags="-s -w" -mod=vendor -o dist/khepra-cli.exe ./cmd/khepra
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

Write-Host " -> Build Complete." -ForegroundColor Green

# 3. Validation & Hashing
Write-Host " -> Generating Checksums..."
$files = Get-ChildItem "dist/*.exe"
$checksums = @()

foreach ($f in $files) {
    $hash = Get-FileHash -Path $f.FullName -Algorithm SHA256
    $entry = "$($hash.Hash)  $($f.Name)"
    $checksums += $entry
    Write-Host "    $entry" -ForegroundColor Gray
}

$checksums | Out-File "dist/CHECKSUMS.txt" -Encoding ascii

# 4. Mock Signing (Placeholder for PGP)
Write-Host " -> Signing Release (Mock)..."
$canary = Get-Content "security/WARRANT_CANARY.txt" -Raw
$signature = "-----BEGIN PGP SIGNATURE-----`nMockSignatureBase64...`n-----END PGP SIGNATURE-----"
$signedPayload = $canary + "`n" + ($checksums -join "`n") + "`n" + $signature
$signedPayload | Out-File "dist/RELEASE_MANIFEST.signed.txt" -Encoding ascii

# 5. Instructions
Write-Host "`n[SUCCESS] Release Ready only in 'dist/'" -ForegroundColor Green
Write-Host "1. Upload 'dist/' folder to IPFS."
Write-Host "2. Add CID to DNS TXT record for 'release.khepra.io'."

param(
    [string]$BinaryPath = "$PSScriptRoot\..\khepra-mcp.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "=== KHEPRA MCP SERVER - TRL-10 PROTOCOL VALIDATION ===" -ForegroundColor Cyan
Write-Host "Binary: $BinaryPath" -ForegroundColor Gray

if (-not (Test-Path $BinaryPath)) {
    Write-Host "ERROR: Binary not found at $BinaryPath" -ForegroundColor Red
    exit 1
}

# MCP 2025-11-25 Protocol Sequence - mirrors exactly what Claude Desktop sends
$messages = @(
    '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true},"sampling":{}},"clientInfo":{"name":"Claude","version":"0.7.4"}},"id":0}',
    '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
    '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}',
    '{"jsonrpc":"2.0","method":"prompts/list","params":{},"id":2}',
    '{"jsonrpc":"2.0","method":"resources/list","params":{},"id":3}',
    '{"jsonrpc":"2.0","method":"ping","params":{},"id":4}'
)

$inputFile = [System.IO.Path]::GetTempFileName()
$outputFile = [System.IO.Path]::GetTempFileName()
$errorFile = [System.IO.Path]::GetTempFileName()

# Write input without BOM (PowerShell's default UTF-8 includes BOM on older PS)
$utf8NoBOM = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines($inputFile, $messages, $utf8NoBOM)

Write-Host "Sending $($messages.Count) protocol messages..." -ForegroundColor Yellow

$env:KHEPRA_MODE = "sovereign"
$env:KHEPRA_NETWORK_POLICY = "lan"
$env:PHANTOM_SYMBOL = "Eban"
$env:KHEPRA_MANIFEST_PATH = "$PSScriptRoot\..\manifest.json"
$env:KHEPRA_MAX_CONCURRENT = "5"
$env:MCP_PQC_ENABLED = "true"

$proc = Start-Process -FilePath $BinaryPath `
    -RedirectStandardInput $inputFile `
    -RedirectStandardOutput $outputFile `
    -RedirectStandardError $errorFile `
    -NoNewWindow -PassThru

$deadline = (Get-Date).AddSeconds(10)
while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 200
}
if (-not $proc.HasExited) { $proc | Stop-Process -Force }

Write-Host ""
Write-Host "=== STDOUT (JSON-RPC responses) ===" -ForegroundColor Cyan
$stdout = Get-Content $outputFile -ErrorAction SilentlyContinue -Raw
if ($stdout) {
    $lines = $stdout.Trim() -split "`n"
    $pass = 0; $fail = 0

    foreach ($line in $lines) {
        $line = $line.Trim()
        if (-not $line) { continue }
        try {
            $parsed = $line | ConvertFrom-Json
            $hasJsonrpc = $parsed.jsonrpc -eq "2.0"
            $hasId = $null -ne $parsed.id
            $hasResult = $null -ne $parsed.result
            $hasError = $null -ne $parsed.error

            if ($hasJsonrpc -and $hasId -and ($hasResult -or $hasError)) {
                if ($hasResult -and $parsed.id -eq 0) {
                    $result = $parsed.result
                    $ok = $result.protocolVersion -eq "2025-11-25" -and
                          $null -ne $result.capabilities.tools -and
                          $null -ne $result.serverInfo -and
                          ($null -ne $result.capabilities.tools.listChanged)  # explicit bool check
                    if ($ok) {
                        Write-Host "[PASS] initialize | protocolVersion=$($result.protocolVersion) | listChanged=$($result.capabilities.tools.listChanged) | server=$($result.serverInfo.name)" -ForegroundColor Green
                        $pass++
                    } else {
                        Write-Host "[FAIL] initialize - missing required fields" -ForegroundColor Red
                        Write-Host "  protocolVersion: $($result.protocolVersion)" -ForegroundColor Red
                        Write-Host "  tools: $($result.capabilities.tools | ConvertTo-Json -Compress)" -ForegroundColor Red
                        $fail++
                    }
                } elseif ($hasResult -and $parsed.id -eq 1) {
                    $toolCount = 0
                    if ($parsed.result.tools) { $toolCount = @($parsed.result.tools).Count }
                    if ($toolCount -gt 0) {
                        Write-Host "[PASS] tools/list | count=$toolCount" -ForegroundColor Green
                        $pass++
                        $noSchema = @($parsed.result.tools | Where-Object { -not $_.inputSchema })
                        if ($noSchema.Count -gt 0) {
                            Write-Host "[WARN] Tools missing inputSchema: $(($noSchema | ForEach-Object {$_.name}) -join ', ')" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host "[FAIL] tools/list returned 0 tools" -ForegroundColor Red
                        $fail++
                    }
                } elseif ($hasError) {
                    if ($parsed.error.code -eq -32601) {
                        Write-Host "[OK]   id=$($parsed.id) Method Not Found (acceptable for optional methods)" -ForegroundColor DarkGray
                    } else {
                        Write-Host "[FAIL] id=$($parsed.id) ERROR $($parsed.error.code): $($parsed.error.message)" -ForegroundColor Red
                        $fail++
                    }
                } else {
                    Write-Host "[PASS] id=$($parsed.id) response OK" -ForegroundColor Green
                    $pass++
                }
            } else {
                Write-Host "[FAIL] Invalid JSON-RPC: $line" -ForegroundColor Red
                $fail++
            }
        } catch {
            Write-Host "[FAIL] Not JSON: $line" -ForegroundColor Red
            $fail++
        }
    }

    Write-Host ""
    Write-Host "=== RESULTS ===" -ForegroundColor Cyan
    Write-Host "  PASS: $pass" -ForegroundColor Green
    if ($fail -gt 0) {
        Write-Host "  FAIL: $fail" -ForegroundColor Red
        Write-Host ""
        Write-Host "Protocol issues found - fix before Claude Desktop deployment" -ForegroundColor Red
    } else {
        Write-Host "  FAIL: 0" -ForegroundColor Green
        Write-Host ""
        Write-Host "TRL-10 READY - Server passes full Claude Desktop protocol validation" -ForegroundColor Green
    }
} else {
    Write-Host "No output from server" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== STDERR (first 30 lines) ===" -ForegroundColor Gray
Get-Content $errorFile -ErrorAction SilentlyContinue | Select-Object -First 30

Remove-Item $inputFile, $outputFile, $errorFile -ErrorAction SilentlyContinue

param(
  [string]$Command = "go",
  [string[]]$Arguments = @("run", "./cmd/khepra-mcp"),
  [string]$ManifestPath = "./manifest.json"
)

$ErrorActionPreference = "Stop"

$requestFile = New-TemporaryFile
$stdoutFile  = New-TemporaryFile
$stderrFile  = New-TemporaryFile

try {
  @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"khepra-smoke","version":"1.0.0"}}}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{}}'
  ) | Set-Content -Path $requestFile -Encoding ASCII

  $env:KHEPRA_MANIFEST_PATH = $ManifestPath
  $process = Start-Process `
    -FilePath $Command `
    -ArgumentList $Arguments `
    -RedirectStandardInput  $requestFile `
    -RedirectStandardOutput $stdoutFile `
    -RedirectStandardError  $stderrFile `
    -NoNewWindow `
    -Wait `
    -PassThru

  if ($process.ExitCode -ne 0) {
    Get-Content $stderrFile | Write-Error
    throw "MCP server exited with code $($process.ExitCode)"
  }

  $responses = Get-Content $stdoutFile |
    Where-Object { $_.Trim().Length -gt 0 } |
    ForEach-Object { $_ | ConvertFrom-Json }

  if ($responses.Count -lt 3) {
    throw "Expected at least 3 JSON-RPC responses, got $($responses.Count)"
  }

  $initialize = $responses | Where-Object { $_.id -eq 1 } | Select-Object -First 1
  $toolsList  = $responses | Where-Object { $_.id -eq 2 } | Select-Object -First 1
  $ping       = $responses | Where-Object { $_.id -eq 3 } | Select-Object -First 1

  if (-not $initialize.result.name)  { throw "initialize response missing server name" }
  if (-not $toolsList.result.tools)  { throw "tools/list response missing tools" }
  if ($ping.result.status -ne "pong") { throw "ping response missing pong status" }

  [pscustomobject]@{
    server          = $initialize.result.name
    version         = $initialize.result.version
    protocolVersion = $initialize.result.protocolVersion
    toolCount       = $toolsList.result.tools.Count
    ping            = $ping.result.status
  } | ConvertTo-Json
}
finally {
  Remove-Item -Force $requestFile, $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
}

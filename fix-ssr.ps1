$files = Get-ChildItem -Recurse -Path "src\app" -Filter "page.tsx"
$count = 0

foreach ($f in $files) {
    # Skip the catch-all [...slug] page (already correct) and API routes
    if ($f.FullName -match '\[') { continue }
    if ($f.FullName -match '\\api\\') { continue }

    $newContent = @(
        '"use client";',
        "import dynamic from 'next/dynamic';",
        "const App = dynamic(() => import('@/App'), { ssr: false });",
        "export default App;"
    )
    Set-Content $f.FullName -Value ($newContent -join "`n")
    $count++
    Write-Host "Fixed: $($f.FullName.Replace('C:\Users\intel\blackbox\PQC-Khepra-MCP\',''))"
}

Write-Host "`nTransformed $count pages to render App.tsx with BrowserRouter"

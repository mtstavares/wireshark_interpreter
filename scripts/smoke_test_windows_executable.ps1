$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Executable = (Resolve-Path (Join-Path $ProjectRoot "release\PCAP-Security-Analyzer.exe")).Path
$SmokeRoot = Join-Path $ProjectRoot ".tmp\launcher-smoke"
New-Item -ItemType Directory -Force -Path $SmokeRoot | Out-Null

$env:LOCALAPPDATA = $SmokeRoot
$env:PCAP_NO_BROWSER = "1"
$Stdout = Join-Path $SmokeRoot "stdout.log"
$Stderr = Join-Path $SmokeRoot "stderr.log"
$Process = Start-Process `
    -FilePath $Executable `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $Stdout `
    -RedirectStandardError $Stderr

try {
    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 120; $Attempt++) {
        try {
            $Health = Invoke-RestMethod `
                -Uri "http://127.0.0.1:8000/healthz" `
                -TimeoutSec 1
            if ($Health.status -eq "ok") {
                $Ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $Ready) {
        throw "O executável não respondeu em até 30 segundos."
    }

    $Page = Invoke-WebRequest `
        -Uri "http://127.0.0.1:8000/" `
        -UseBasicParsing `
        -TimeoutSec 5
    $Database = Join-Path $SmokeRoot "PCAP Security Analyzer\app.db"
    if ($Page.StatusCode -ne 200 -or -not (Test-Path $Database)) {
        throw "A interface ou o banco de dados não foi inicializado corretamente."
    }
    Write-Host "Smoke test aprovado: health, frontend e banco de dados disponíveis."
}
finally {
    $Children = Get-CimInstance Win32_Process | Where-Object {
        $_.ParentProcessId -eq $Process.Id -and $_.ExecutablePath -eq $Executable
    }
    $Children | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
}

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Frontend = Join-Path $ProjectRoot "frontend"
$Release = Join-Path $ProjectRoot "release"

if (-not (Test-Path $Python)) {
    throw "Ambiente virtual não encontrado em $Python"
}

Push-Location $Frontend
try {
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar o frontend" }
}
finally {
    Pop-Location
}

& $Python -m pip install "pyinstaller>=6.16,<7"
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar o PyInstaller" }

New-Item -ItemType Directory -Force -Path $Release | Out-Null

Push-Location $ProjectRoot
try {
    & $Python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --name "PCAP-Security-Analyzer" `
        --distpath $Release `
        --workpath (Join-Path $ProjectRoot "build\pyinstaller") `
        --specpath (Join-Path $ProjectRoot "build") `
        --add-data "$ProjectRoot\frontend\dist;frontend/dist" `
        --add-data "$ProjectRoot\backend\app\migrations;backend/app/migrations" `
        --collect-data alembic `
        --collect-data reportlab `
        "backend/app/launcher.py"
    if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar o executável" }
}
finally {
    Pop-Location
}

Write-Host "Executável criado em: $Release\PCAP-Security-Analyzer.exe"

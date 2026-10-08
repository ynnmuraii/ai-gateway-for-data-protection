$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$postgresControl = Join-Path $projectRoot '.runtime\postgresql\pgsql\bin\pg_ctl.exe'
$postgresData = Join-Path $projectRoot '.runtime\pgdata'
& $postgresControl -D $postgresData status *> $null
if ($LASTEXITCODE -ne 0) { & $postgresControl -D $postgresData -l (Join-Path $projectRoot '.runtime\postgres.log') -w start }
if (-not (Test-Path -LiteralPath 'frontend\dist\index.html')) { throw 'Build frontend first: cd frontend; npm ci; npm run build' }
& '.\.venv\Scripts\python.exe' -m uvicorn gateway.main:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers

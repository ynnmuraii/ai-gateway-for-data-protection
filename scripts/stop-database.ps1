$projectRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $projectRoot '.runtime\postgresql\pgsql\bin\pg_ctl.exe') -D (Join-Path $projectRoot '.runtime\pgdata') -m fast -w stop

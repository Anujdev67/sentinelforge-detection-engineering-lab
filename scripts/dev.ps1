param(
    [ValidateSet('setup', 'demo', 'native-demo', 'test', 'lint', 'validate', 'up', 'down', 'api', 'native-api', 'dashboard')]
    [string]$Command = 'setup'
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Operation
    )

    & $Operation
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE."
    }
}

Push-Location $RepositoryRoot
try {
    switch ($Command) {
        'setup' {
            Invoke-Checked { python -m scripts.create_env }
            Invoke-Checked { python -m pip install -e ".[dev]" }
            Push-Location apps/dashboard
            try { Invoke-Checked { pnpm install --frozen-lockfile } } finally { Pop-Location }
        }
        'demo' { Invoke-Checked { docker compose exec api python -m scripts.demo } }
        'native-demo' {
            $env:SENTINELFORGE_DEMO_MODE = 'true'
            $env:SENTINELFORGE_DATABASE_URL = 'sqlite:///./sentinelforge-demo.db'
            $env:SENTINELFORGE_CORS_ORIGINS = 'http://localhost:5173'
            Invoke-Checked { python -m scripts.demo }
        }
        'test' {
            Invoke-Checked { python -m pytest }
            Push-Location apps/dashboard
            try { Invoke-Checked { pnpm test } } finally { Pop-Location }
        }
        'lint' {
            Invoke-Checked { python -m ruff check . }
            Invoke-Checked { python -m mypy apps detections evaluators telemetry soar scripts tests }
            Push-Location apps/dashboard
            try {
                Invoke-Checked { pnpm lint }
                Invoke-Checked { pnpm exec tsc -b --pretty false }
            }
            finally { Pop-Location }
        }
        'validate' {
            Invoke-Checked { & $PSCommandPath test }
            Invoke-Checked { & $PSCommandPath lint }
            Invoke-Checked { python -m scripts.validate_content }
            Invoke-Checked { python -m scripts.check_links }
            Push-Location apps/dashboard
            try { Invoke-Checked { pnpm build } } finally { Pop-Location }
            Push-Location infrastructure/terraform
            try {
                Invoke-Checked { terraform fmt -check -recursive }
                Invoke-Checked { terraform validate }
            }
            finally { Pop-Location }
            Invoke-Checked { docker compose config --quiet }
        }
        'up' { Invoke-Checked { docker compose up --build } }
        'down' { Invoke-Checked { docker compose down } }
        'api' { Invoke-Checked { python -m uvicorn apps.api.sentinelforge_api.main:app --reload } }
        'native-api' {
            $env:SENTINELFORGE_DEMO_MODE = 'true'
            $env:SENTINELFORGE_DATABASE_URL = 'sqlite:///./sentinelforge-demo.db'
            $env:SENTINELFORGE_CORS_ORIGINS = 'http://localhost:5173'
            Invoke-Checked { python -m uvicorn apps.api.sentinelforge_api.main:app --reload }
        }
        'dashboard' {
            Push-Location apps/dashboard
            try { Invoke-Checked { pnpm dev } } finally { Pop-Location }
        }
    }
}
finally {
    Pop-Location
}

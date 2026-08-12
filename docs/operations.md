# Local operations runbook

## Container workflow

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
docker compose exec api python -m scripts.demo
```

Expected demo summary: 12 alerts and 10 incidents. The exact deterministic incident IDs are printed by the command. Open `http://localhost:5173`; API health is `http://localhost:8000/api/v1/health`.

Stop services without deleting the database volume:

```powershell
docker compose down
```

Deleting the volume is intentionally not part of a project command. The guarded demo reset deletes rows only from known SentinelForge tables.

## Native workflow

Use Python 3.12 and Node 24 with pnpm 11. In VS Code, open the repository folder and create two PowerShell terminals with **Terminal → New Terminal**.

In terminal 1, seed the guarded SQLite demo and start FastAPI:

```powershell
.\.venv\Scripts\Activate.ps1
.\scripts\dev.ps1 native-demo
.\scripts\dev.ps1 native-api
```

In terminal 2, start Vite:

```powershell
.\.venv\Scripts\Activate.ps1
.\scripts\dev.ps1 dashboard
```

Open `http://localhost:5173`. API health is `http://localhost:8000/api/v1/health` and interactive API documentation is `http://localhost:8000/docs`. Stop each native server with `Ctrl+C` in its terminal.

## Health and troubleshooting

| Symptom | Check | Resolution |
| --- | --- | --- |
| Dashboard says API unavailable | `/api/v1/health` | Confirm API/database health and dashboard proxy |
| Demo refuses reset | `SENTINELFORGE_DEMO_MODE` and DB name | Use only `sentinelforge_demo` or `sentinelforge-demo.db` |
| No incidents | demo output and `/api/v1/alerts` | Re-run the guarded demo; evaluation is idempotent after reset |
| Frontend proxy error | Vite output and port 8000 | Start API first or use Compose |
| Terraform init fails | outbound access to HashiCorp registry | Run in CI or a network that can download the pinned provider |

## Test and validation commands

```powershell
python -m pytest
python -m ruff check .
python -m mypy apps detections evaluators telemetry soar scripts tests
python -m scripts.validate_content
Push-Location apps/dashboard
pnpm lint
pnpm test
pnpm build
Pop-Location
```

When Terraform and Docker are installed:

```powershell
Push-Location infrastructure/terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
Pop-Location
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example build
```

No repository command invokes an Azure deployment.

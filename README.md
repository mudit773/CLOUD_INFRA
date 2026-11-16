# InfraScope

InfraScope analyzes Terraform projects, builds an interactive infrastructure and attack-path graph, identifies security findings, and can request remediation suggestions from a locally hosted Ollama model.

## Architecture

```text
Browser
  React + Vite production build, served by Nginx
       │ same-origin /api proxy
       ▼
  FastAPI bridge (server.py)
       │ runs the parser and analysis pipeline
       ▼
  Python Terraform parser, graph and security analysis

FastAPI ── local HTTP ──> Ollama on the host machine
```

- **Frontend:** React pages for uploads, graph visualization, and AI insights. Nginx serves the production build and proxies `/api` requests to the backend.
- **Backend:** FastAPI accepts Terraform files, runs the Python parser/security pipeline, and returns graph and finding data.
- **Local AI:** `llm_service.py` sends remediation prompts to the Ollama service configured by `OLLAMA_URL`. Terraform analysis runs locally; source files and prompts are not sent to a hosted AI service.

## Run with Docker Compose

### Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin.
- Ollama installed and running on the host machine.

### 1. Prepare Ollama

Start Ollama and download a model once. The default model is:

```sh
ollama pull qwen2.5-coder:1.5b
```

You can use another installed model by setting `OLLAMA_MODEL` before starting Compose. For example, in PowerShell:

```powershell
$env:OLLAMA_MODEL = "qwen2.5-coder:1.5b"
```

Compose connects from the backend container to `http://host.docker.internal:11434`. If Ollama is not reachable at that address, configure Ollama to listen on a host interface reachable by Docker and restrict access with your host firewall to local/Docker traffic. Do not expose the Ollama port to the public internet. You can override `OLLAMA_URL` and `OLLAMA_TAGS_URL` if your Ollama endpoint differs.

### 2. Build and launch

From the repository root:

```sh
docker compose up --build
```

Open [http://localhost:5173](http://localhost:5173). The backend health endpoint is available at [http://localhost:8000/api/health](http://localhost:8000/api/health).

The compose file mounts built-in Terraform scenarios read-only and persists generated output and uploaded files in `input/uploads` and `output`. Stop the application with `Ctrl+C`; run `docker compose down` to remove the containers. Bind-mounted project data remains on the host.

Folder paths entered in the application must be paths visible inside the backend container. Built-in scenarios under `input/terraform` are already mounted. To scan another host directory by path, add a read-only bind mount for it to the backend service in `docker-compose.yml`, or upload its Terraform files/ZIP instead.

### Configure Ollama

The default model is `qwen2.5-coder:1.5b`. Set a different model name before running Compose:

```powershell
$env:OLLAMA_MODEL = "your-installed-model"
docker compose up --build
```

Or set `OLLAMA_MODEL` in a root `.env` file. The model must already be installed in the host Ollama instance (use `ollama pull <model>`). The container does not download or run a separate Ollama model.

## Local development (without Docker)

Requirements: Python 3.10+ and Node.js 22+.

```sh
python -m pip install -r requirements.txt
npm --prefix frontend ci
```

Start the backend and frontend in separate terminals:

```sh
python server.py
npm --prefix frontend run dev
```

The development frontend is at [http://localhost:5173](http://localhost:5173) and proxies API requests to port 8000. For local development, the default Ollama endpoint is `http://localhost:11434/api/generate`.

## Use the command-line analyzer

```sh
python main.py -i input/terraform/aws_vpc_msk -o output/terraform.json --summary
```

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Backend and Ollama status |
| `POST` | `/api/upload` | Upload Terraform files or a ZIP archive and analyze |
| `POST` | `/api/scan` | Analyze a project directory available to the backend |
| `GET` | `/api/graph` | Fetch graph nodes, edges, findings, and summary |
| `GET` | `/api/findings` | Fetch security findings and risk summary |
| `GET` / `POST` | `/api/remediate` | Generate remediation suggestions using local Ollama |

## Tests

```sh
pytest
```

#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$PROJECT_DIR/n8n/docker-compose.yml"
ENV_FILE="$PROJECT_DIR/.env"

# ---------- colours ----------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error() { printf "${RED}[-]${NC} %s\n" "$*"; }

# ---------- pre-flight checks ----------
check_docker() {
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. Install Docker Desktop first."
        exit 1
    fi
    if ! docker info &>/dev/null; then
        error "Docker daemon is not running. Start Docker Desktop first."
        exit 1
    fi
}

check_env() {
    if [ ! -f "$ENV_FILE" ]; then
        warn ".env file not found — copying from .env.example"
        if [ -f "$PROJECT_DIR/.env.example" ]; then
            cp "$PROJECT_DIR/.env.example" "$ENV_FILE"
            warn "Edit $ENV_FILE with your target credentials before running an assessment."
        else
            error ".env.example not found. Create a .env file manually."
            exit 1
        fi
    fi
}

ensure_dirs() {
    mkdir -p "$PROJECT_DIR/output"
}

# ---------- main ----------
main() {
    info "Embedded Assessment Platform — Deploy"
    echo ""

    check_docker
    info "Docker is available"

    check_env
    ensure_dirs

    info "Building and starting containers..."
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

    echo ""
    info "Waiting for services to become healthy..."

    # Poll health endpoints (configurable via DEPLOY_HEALTH_TIMEOUT env var)
    MAX_WAIT="${DEPLOY_HEALTH_TIMEOUT:-60}"
    INTERVAL=2

    # Health check — collector
    elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if curl -sf http://localhost:8000/health &>/dev/null; then
            info "Collector API    : http://localhost:8000  (healthy)"
            break
        fi
        sleep "$INTERVAL"
        elapsed=$((elapsed + INTERVAL))
    done
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        warn "Collector API    : http://localhost:8000  (not healthy after ${MAX_WAIT}s)"
    fi

    # Health check — n8n
    elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if curl -sf http://localhost:5678 &>/dev/null; then
            info "n8n Dashboard    : http://localhost:5678  (healthy)"
            break
        fi
        sleep "$INTERVAL"
        elapsed=$((elapsed + INTERVAL))
    done
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        warn "n8n Dashboard    : http://localhost:5678  (not healthy after ${MAX_WAIT}s)"
    fi

    echo ""
    info "Deployment complete. Use ./teardown.sh to stop all services."
}

main "$@"

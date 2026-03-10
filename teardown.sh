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

# ---------- flags ----------
REMOVE_VOLUMES=false
REMOVE_IMAGES=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --volumes    Remove named volumes (n8n data, SSH keys)"
    echo "  -i, --images     Remove built images"
    echo "  -a, --all        Remove volumes and images"
    echo "  -h, --help       Show this help"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--volumes) REMOVE_VOLUMES=true; shift ;;
        -i|--images)  REMOVE_IMAGES=true; shift ;;
        -a|--all)     REMOVE_VOLUMES=true; REMOVE_IMAGES=true; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ---------- main ----------
info "Embedded Assessment Platform — Teardown"
echo ""

COMPOSE_ARGS=(-f "$COMPOSE_FILE")
[ -f "$ENV_FILE" ] && COMPOSE_ARGS+=(--env-file "$ENV_FILE")

info "Stopping containers..."
docker compose "${COMPOSE_ARGS[@]}" down

if $REMOVE_VOLUMES; then
    warn "Removing named volumes (n8n_data, collector_ssh)..."
    docker volume rm n8n_n8n_data n8n_collector_ssh 2>/dev/null || true
fi

if $REMOVE_IMAGES; then
    warn "Removing built collector image..."
    docker rmi n8n-collector 2>/dev/null || true
fi

echo ""
info "All services stopped."

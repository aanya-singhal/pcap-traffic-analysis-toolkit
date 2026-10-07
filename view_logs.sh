#!/usr/bin/env bash
# ==============================================================================
# PCAP Traffic Analysis Toolkit - Live Container Logs Viewer
# Follows and streams logs from all 3 demo containers:
#   - pcap-receiver (Dashboard & analysis victim)
#   - pcap-attacker (SYN scan & brute force generator)
#   - pcap-client   (Benign web traffic generator)
# ==============================================================================

set -e

# Change to project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if Docker Compose is available
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Error: docker is not installed or not in PATH."
    exit 1
fi

# Check if containers are running
RUNNING_CONTAINERS=$(docker compose ps --services --filter "status=running" 2>/dev/null || true)
if [ -z "$RUNNING_CONTAINERS" ]; then
    echo "[!] No demo containers are currently running."
    echo "[*] Starting containers with 'docker compose up -d'..."
    docker compose up -d
fi

echo "=================================================================="
echo " Streaming logs from PCAP Toolkit containers..."
echo " Target services: receiver, attacker, client"
echo " Press Ctrl+C at any time to stop streaming."
echo "=================================================================="
echo ""

# If an argument is provided (e.g., ./view_logs.sh attacker), tail that specific service.
# Otherwise, tail all three with timestamp indicators and follow (-f).
if [ $# -gt 0 ]; then
    docker compose logs -f --tail 30 "$@"
else
    docker compose logs -f --tail 20 receiver attacker client
fi

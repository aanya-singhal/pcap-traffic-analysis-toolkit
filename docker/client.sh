#!/bin/sh
# Legit client container: generates a steady stream of normal web requests to
# the receiver's dashboard so the capture has a realistic benign baseline. This
# is the traffic the attacker's scan/brute-force must stand out against.
set -eu

TARGET="${TARGET:-receiver}"
PORT="${PORT:-5001}"
BASE="http://${TARGET}:${PORT}"

echo "[client] generating normal web traffic to ${BASE}"

while true; do
    for path in / / /analysis/1 /; do
        curl -s -o /dev/null --max-time 5 "${BASE}${path}" || true
        sleep 1
    done
done

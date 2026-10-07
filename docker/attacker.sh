#!/bin/sh
# Attacker container: continuously scans and "brute-forces" the receiver so that
# any live-capture window on the receiver catches hostile traffic in progress.
#
# This is a self-contained lab against our own receiver container on a private
# Docker network. Both actions produce exactly the SYN patterns the toolkit's
# Port Scan / Brute Force / Suspicious Port rules look for.
set -eu

TARGET="${TARGET:-receiver}"

echo "[attacker] targeting ${TARGET}; looping scan + brute-force bursts"

while true; do
    # --- Port scan: one SYN to each of many distinct ports (incl. two known
    #     backdoor ports) -> trips Port Scan + Suspicious Port.
    echo "[attacker] port scan"
    nmap -sS -Pn -n --max-retries 0 --host-timeout 15s \
        -p 1-150,4444,31337 "${TARGET}" >/dev/null 2>&1 || true

    # --- Brute force: a burst of connection attempts to SSH (port 22) ->
    #     trips Brute Force (>= 20 SYNs to a login port within the window).
    echo "[attacker] ssh brute-force burst"
    i=0
    while [ "$i" -lt 30 ]; do
        nmap -sS -Pn -n --max-retries 0 -p 22 "${TARGET}" >/dev/null 2>&1 || true
        i=$((i + 1))
    done

    sleep 3
done

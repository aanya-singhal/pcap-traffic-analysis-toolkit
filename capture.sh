#!/usr/bin/env bash
set -e

# Default parameters
INTERFACE="${1:-wlo1}"
DURATION="${2:-20}"
OUTPUT_FILE="${3:-capture_${DURATION}s.pcap}"

# Determine command to run based on current group membership
run_capture() {
    # If the current shell doesn't recognize the wireshark group yet, use sg
    if ! id -nG | grep -qw "wireshark"; then
        exec sg wireshark -c "tshark -i \"$INTERFACE\" -a duration:\"$DURATION\" -w \"$OUTPUT_FILE\""
    else
        exec tshark -i "$INTERFACE" -a duration:"$DURATION" -w "$OUTPUT_FILE"
    fi
}

echo "Starting capture on interface '$INTERFACE' for ${DURATION}s..."
echo "Output will be saved to: $OUTPUT_FILE"

run_capture

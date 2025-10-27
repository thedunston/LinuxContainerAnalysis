#!/bin/bash

# Full ltrace wrapper for malware analysis.
# Captures library calls traces with all arguments.

MALWARE_FILE="$1"
OUTPUT_DIR="/tmp/ltrace_analysis"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$MALWARE_FILE" ]; then
    echo "Usage: $0 <malware_binary> [additional_args...]"
    echo "Example: $0 ./thug_simulator"
    exit 1
fi

if [ ! -f "$MALWARE_FILE" ]; then
    echo "Error: File '$MALWARE_FILE' not found"
    exit 1
fi

# Create output directory.
mkdir -p "$OUTPUT_DIR"

# Shift to get additional arguments.
shift
EXTRA_ARGS="$@"

# Output files.
RAW_OUTPUT="$OUTPUT_DIR/ltrace_raw_${TIMESTAMP}.txt"
BEHAVIOR_OUTPUT="$OUTPUT_DIR/ltrace_behavior_${TIMESTAMP}.txt"

echo "[*] Starting full ltrace analysis..."
echo "[*] Target: $MALWARE_FILE"
echo "[*] Output directory: $OUTPUT_DIR"
echo "[*] Raw output: $RAW_OUTPUT"
echo ""

# Run ltrace with full options.
# -s 4096: String length (capture full strings).
# -n 4: Indent nested calls.
# -f: Follow forks.
# -tt: Absolute timestamps with microseconds.
# -T: Show time spent in each call.
# -o: Output file
ltrace -s 4096 -n 4 -f -tt -T -o "$RAW_OUTPUT" "$MALWARE_FILE" $EXTRA_ARGS

echo ""
echo "[*] ltrace completed"
echo "[*] Raw output saved to: $RAW_OUTPUT"
echo ""
echo "[*] Parsing output for readability..."

# Parse the output - Technical Analysis.
# Try to find parsers in multiple locations (container vs host).
PARSER_LOCATIONS=(
    "/usr/local/bin"
    "$(dirname "$0")"
    "."
)

# Find the parser directory.
PARSER_DIR=""
for loc in "${PARSER_LOCATIONS[@]}"; do
    if [ -f "$loc/parse-ltrace-behavior.py" ]; then
        PARSER_DIR="$loc"
        break
    fi
done

# Parse the output - Behavioral Analysis.
if [ -n "$PARSER_DIR" ] && [ -f "$PARSER_DIR/parse-ltrace-behavior.py" ]; then
    echo "[*] Running behavioral analysis parser..."
    python3 "$PARSER_DIR/parse-ltrace-behavior.py" "$RAW_OUTPUT" "$BEHAVIOR_OUTPUT"
    echo "[✓] Behavioral analysis saved to: $BEHAVIOR_OUTPUT"
else
    echo "[!] Behavioral parser not found."
fi

echo ""
echo "[*] Analysis Complete!"
echo "[*] ============================================"
echo "[*] Output Files:"
echo "    1. Raw ltrace output:      $RAW_OUTPUT"
echo "    2. Behavioral analysis:    $BEHAVIOR_OUTPUT"
echo ""
echo "[*] Quick Commands:"
echo "    - View behavioral report:  cat $BEHAVIOR_OUTPUT"
echo "    - Search for tactics:      grep 'Phase' $BEHAVIOR_OUTPUT"
echo "    - View suspicious acts:    grep 'SUSPICIOUS' $BEHAVIOR_OUTPUT"
echo "    - View IOCs:               grep 'IOC' $BEHAVIOR_OUTPUT"

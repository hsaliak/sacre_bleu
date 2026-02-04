#!/bin/bash
set -e

GEN=$1
INJECTOR=$2
LOADER=$3
TARGET=$4
OUTPUT_INI="/tmp/sacre_gen_test.ini"
TARGET_COPY="/tmp/minimal_target_gen_test"

echo "Testing gen..."
echo "Gen: $GEN"
echo "Target: $TARGET"

# 1. Generate policy
"$GEN" "$OUTPUT_INI" "$TARGET"

if [ ! -f "$OUTPUT_INI" ]; then
    echo "Error: Generator did not create $OUTPUT_INI"
    exit 1
fi

echo "Generated policy:"
cat "$OUTPUT_INI"

# 2. Verify policy has some expected syscalls
grep -q "execve" "$OUTPUT_INI" || (echo "Error: policy missing execve"; exit 1)
grep -q "write" "$OUTPUT_INI" || (echo "Error: policy missing write"; exit 1)

# 3. Inject and run to verify it works
"$INJECTOR" "$OUTPUT_INI" "$TARGET" "$TARGET_COPY"
chmod +x "$TARGET_COPY"
"$LOADER" "$TARGET_COPY"

echo "gen integration test passed."

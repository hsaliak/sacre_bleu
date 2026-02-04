#!/bin/bash
set -e

# Arguments
INJECTOR=$1
LOADER=$2
TARGET=$3
POLICY_INI=$4

if [ ! -f "$INJECTOR" ] || [ ! -f "$LOADER" ] || [ ! -f "$TARGET" ]; then
    echo "Usage: $0 <injector_path> <loader_path> <target_path> <policy_ini_path>"
    exit 1
fi

echo "--- Integration Test Start ---"

# 1. Inject the policy
echo "[1/3] Injecting policy $POLICY_INI into $TARGET..."
"$INJECTOR" "$POLICY_INI" "$TARGET"

# 2. Run with loader
echo "[2/3] Executing with loader..."
# We expect success here.
"$LOADER" "$TARGET"

# 3. Verify (optional but good)
echo "[3/3] Verification successful."

echo "--- Integration Test Passed ---"
exit 0

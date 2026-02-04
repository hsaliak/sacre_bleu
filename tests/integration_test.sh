#!/bin/bash
# Integration test for bleu-loader / sacre-inject

INJECTOR=$1
LOADER=$2
TARGET=$3
POLICY=$4
shift 4

echo "Injector: $INJECTOR"
echo "Loader: $LOADER"
echo "Target: $TARGET"
echo "Policy: $POLICY"

# 1. Inject
"$INJECTOR" "$POLICY" "$TARGET"

# 2. Run
echo "Running: $LOADER $TARGET $@"
"$LOADER" "$TARGET" "$@"
RET=$?

if [ "$EXPECT_KILL" == "1" ]; then
    if [ $RET -ne 0 ]; then
        echo "Successfully caught expected failure/kill (Exit code: $RET)"
        exit 0
    else
        echo "Error: Expected process to be killed, but it exited successfully."
        exit 1
    fi
else
    if [ $RET -eq 0 ]; then
        echo "Success."
        exit 0
    else
        echo "Error: Process failed with exit code $RET"
        exit $RET
    fi
fi

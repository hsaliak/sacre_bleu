#!/bin/bash
set -e

# Create temporary directory for tests
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Create two dummy INI policies
cat <<EOF > "$TEST_DIR/p1.ini"
[seccomp]
allow = read, write

[landlock]
ro = /usr/lib
EOF

cat <<EOF > "$TEST_DIR/p2.ini"
[seccomp]
allow = exit, read

[landlock]
ro = /lib64
rw = /tmp
EOF

# Merge them
./build/sb-gen merge -o "$TEST_DIR/merged.ini" "$TEST_DIR/p1.ini" "$TEST_DIR/p2.ini"

# Verify content of merged.ini
grep -q "allow = read, write, exit" "$TEST_DIR/merged.ini"
grep -q "ro = /usr/lib, /lib64" "$TEST_DIR/merged.ini"
grep -q "rw = /tmp" "$TEST_DIR/merged.ini"

echo "Integration test for sb-gen merge passed."

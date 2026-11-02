#!/usr/bin/env bash
# ==============================================================================
# LUME Security Toolkit - One-Touch Local Verification & Demo
# Runs the synthetic vulnerable fixture server and scans it with LUME.
# Compatible with Kali Linux, macOS, and Linux bash environments.
# ==============================================================================

set -e

PORT=8005
TARGET="http://127.0.0.1:${PORT}"

echo "=========================================================="
echo " Starting LUME Security Scanner One-Touch Demo"
echo " Target: ${TARGET}"
echo "=========================================================="

# 1. Start synthetic vulnerable server in background
python3 -m tests.fixtures.vulnerable_ai.server --port ${PORT} &
SERVER_PID=$!

cleanup() {
    echo "Stopping test fixture server (PID: ${SERVER_PID})..."
    kill ${SERVER_PID} 2>/dev/null || true
}
trap cleanup EXIT

# Give server time to bind
sleep 1

# 2. Run LUME security scan against local fixture
echo "Executing LUME prompt injection scan..."
lume scan prompt-injection --target "${TARGET}" --authorized --output table

echo ""
echo "=========================================================="
echo " Demo scan completed successfully."
echo " Check the reports/ directory for structured JSON audit logs."
echo "=========================================================="

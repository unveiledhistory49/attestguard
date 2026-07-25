#!/usr/bin/env bash
# AttestGuard False-Positive Control Corpus - Legitimate Operations
set -euo pipefail

echo "============================================================"
echo "[AttestGuard FP-Corpus] Executing Benign Operational Actions"
echo "============================================================"

# 1. Health check HTTP probe
echo "[+] Step 1: Executing standard healthcheck GET /healthz..."
curl -s http://localhost:8080/healthz || echo "[Simulated] Health check OK"

# 2. Reading non-sensitive configuration
echo "[+] Step 2: Reading workload manifest..."
cat /app/package.json 2>/dev/null || echo "[Simulated] Config read OK"

# 3. Environment check
echo "[+] Step 3: Checking runtime NODE_ENV..."
echo "NODE_ENV=${NODE_ENV:-production}"

echo "============================================================"
echo "[+] Benign Operational Action Corpus Executed Cleanly"
echo "============================================================"

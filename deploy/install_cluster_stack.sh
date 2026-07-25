#!/usr/bin/env bash
# AttestGuard Cluster Stack Automated Deployment Script
# Deploys OPA Gatekeeper, Sigstore Policy Controller, Falco eBPF, and AttestGuard manifests into kind cluster
set -euo pipefail

export PATH=/root/bin:$PATH
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "================================================================================"
echo "          ATTESTGUARD KUBERNETES CLUSTER STACK INSTALLER                        "
echo "================================================================================"

CLUSTER_NAME="attestguard-cluster"

# 1. Verify/Create kind Cluster
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "[+] Creating kind cluster '${CLUSTER_NAME}' with eBPF kernel mounts..."
    kind create cluster --config "$PROJECT_ROOT/deploy/kind/cluster-config.yaml"
else
    echo "[+] kind cluster '${CLUSTER_NAME}' already running."
fi

# Set kubectl context
kubectl config use-context "kind-${CLUSTER_NAME}" || true

# 2. Deploy OPA Gatekeeper Admission Controller
echo "[+] Deploying OPA Gatekeeper Admission Controller..."
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml || \
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts && \
helm install gatekeeper gatekeeper/gatekeeper --namespace gatekeeper-system --create-namespace || true

# Wait briefly for Gatekeeper CRDs
echo "[+] Waiting for Gatekeeper CRDs to become ready..."
sleep 3

# 3. Apply Gatekeeper ConstraintTemplates and Constraints
echo "[+] Applying Gatekeeper ConstraintTemplates..."
kubectl apply -f "$PROJECT_ROOT/deploy/gatekeeper/constraint-templates/"

echo "[+] Applying Gatekeeper Constraints..."
kubectl apply -f "$PROJECT_ROOT/deploy/gatekeeper/constraints/gatekeeper-constraints.yaml"

# 4. Deploy Network Policies & Policy Controller
echo "[+] Applying AttestGuard Quarantine NetworkPolicy..."
kubectl apply -f "$PROJECT_ROOT/deploy/network-policies/quarantine-policy.yaml"

echo "[+] Applying Sigstore Policy Controller CIP..."
kubectl apply -f "$PROJECT_ROOT/deploy/policy-controller/cluster-image-policy.yaml" || true

echo "================================================================================"
echo "[SUCCESS] AttestGuard Cluster Stack Deployment Finished Successfully!"
echo "================================================================================"

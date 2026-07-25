# AttestGuard Master Automation Makefile
.PHONY: all setup test-rego test-response redteam benign test-e2e sbom scan clean help

PATH := /root/bin:$(PATH)
SHELL := /bin/bash

all: test-rego test-response test-e2e

setup:
	@echo "==> Verifying system security tools..."
	@export PATH=/root/bin:$$PATH && \
	opa version && \
	cosign version && \
	syft version && \
	trivy version && \
	slsa-verifier version && \
	kubectl version --client && \
	helm version
	@echo "[+] All security binaries verified."

test-rego:
	@echo "==> Executing OPA Rego Admission Policy Unit Tests..."
	@export PATH=/root/bin:$$PATH && \
	opa test deploy/gatekeeper/policies/ tests/rego/ -v

test-response:
	@echo "==> Executing Response Service Unit & Integration Tests..."
	@python3 apps/response-service/test_app.py

redteam:
	@echo "==> Executing Red-Team Adversary Emulation Suite..."
	@bash tests/redteam/exploit_rce.sh

benign:
	@echo "==> Executing Benign Activity False-Positive Corpus..."
	@bash tests/redteam/benign_activity.sh

test-e2e:
	@echo "==> Launching AttestGuard E2E Verification Harness..."
	@export PATH=/root/bin:$$PATH && \
	bash tests/e2e/run_e2e.sh

sbom:
	@echo "==> Generating Syft SBOM..."
	@export PATH=/root/bin:$$PATH && \
	syft dir:apps/target-service -o json > sbom.json && \
	echo "[+] SBOM generated at sbom.json"

scan:
	@echo "==> Running Trivy Vulnerability Scanner..."
	@export PATH=/root/bin:$$PATH && \
	trivy fs apps/target-service --severity HIGH,CRITICAL

clean:
	@echo "==> Cleaning transient build and test artifacts..."
	@rm -f sbom.json /tmp/target-service-sbom.json /tmp/trivy-scan-report.json /tmp/test_revoked_digests.json /tmp/attestguard_revoked_digests.json
	@echo "[+] Cleanup complete."

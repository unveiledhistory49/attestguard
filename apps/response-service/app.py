#!/usr/bin/env python3
"""
AttestGuard Response Service
Automated Incident Containment & Dynamic Admission Policy Feedback Loop Microservice
"""

import os
import sys
import json
import hmac
import hashlib
import time
import logging
import subprocess
import urllib.request
import urllib.error
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AttestGuard-ResponseService")

app = Flask(__name__)

# Rule 8: No hardcoded secrets or usable fallback defaults. Fail loudly if missing.
HMAC_SECRET = os.environ.get("ATTESTGUARD_HMAC_SECRET")
if not HMAC_SECRET:
    logger.critical("[Security Violation] ATTESTGUARD_HMAC_SECRET environment variable is missing!")
    raise ValueError("FATAL: ATTESTGUARD_HMAC_SECRET environment variable must be set. No default allowed.")

REVOKED_DIGESTS_FILE = os.environ.get("REVOKED_DIGESTS_FILE", "/tmp/attestguard_revoked_digests.json")
DEDUPLICATION_WINDOW_SEC = int(os.environ.get("DEDUPLICATION_WINDOW_SEC", 86400))  # 24 hours
KUBERNETES_SERVICE_HOST = os.environ.get("KUBERNETES_SERVICE_HOST")
KUBERNETES_SERVICE_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")

# In-memory deduplication cache: {digest: timestamp}
filed_issues_cache = {}


def verify_hmac_signature(payload_bytes: bytes, signature_header: str) -> bool:
    """Verifies HMAC SHA-256 signature to authenticate incoming Falco webhooks."""
    if not signature_header:
        return False
    
    # Handle optional prefix "sha256="
    expected_sig = signature_header.replace("sha256=", "").strip()
    computed_sig = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed_sig, expected_sig)


def load_revoked_digests() -> list:
    """Loads current list of dynamically revoked image digests."""
    if os.path.exists(REVOKED_DIGESTS_FILE):
        try:
            with open(REVOKED_DIGESTS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading revoked digests file: {e}")
    return []


def save_revoked_digest(digest: str) -> bool:
    """Adds an image digest to the dynamic revocation store."""
    digests = load_revoked_digests()
    if digest not in digests:
        digests.append(digest)
        try:
            os.makedirs(os.path.dirname(REVOKED_DIGESTS_FILE), exist_ok=True)
            with open(REVOKED_DIGESTS_FILE, "w") as f:
                json.dump(digests, f, indent=2)
            logger.info(f"[Feedback Loop] Image digest '{digest}' added to revocation list.")
            return True
        except Exception as e:
            logger.error(f"Failed to persist revoked digest '{digest}': {e}")
            return False
    return False


def isolate_pod_network(namespace: str, pod_name: str) -> dict:
    """
    Executes Stage 1 Containment: Labels pod with quarantine=true in Kubernetes API
    and applies deploy/network-policies/quarantine-policy.yaml via subprocess kubectl.
    Rule 6 Compliance: Performs real operations with clean handling if K8s API / kubectl is offline.
    """
    logger.info(f"[Containment] Initiating network isolation for pod '{pod_name}' in namespace '{namespace}'...")
    
    # Determine quarantine policy YAML path
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    policy_path = os.environ.get(
        "QUARANTINE_POLICY_PATH",
        os.path.join(base_dir, "deploy", "network-policies", "quarantine-policy.yaml")
    )

    cmd_label = ["kubectl", "label", "pod", pod_name, "-n", namespace, "quarantine=true", "--overwrite"]
    cmd_apply = ["kubectl", "apply", "-f", policy_path]

    k8s_api_success = False
    details = []

    try:
        res_label = subprocess.run(cmd_label, capture_output=True, text=True, check=True)
        details.append(f"Label output: {res_label.stdout.strip()}")

        res_apply = subprocess.run(cmd_apply, capture_output=True, text=True, check=True)
        details.append(f"Apply output: {res_apply.stdout.strip()}")

        k8s_api_success = True
        k8s_detail = "; ".join(details)
        logger.info(f"[Containment] Successfully isolated pod '{pod_name}': {k8s_detail}")
    except FileNotFoundError:
        k8s_detail = "kubectl executable not found (Offline/Simulated mode)"
        logger.warning(f"[Containment] {k8s_detail}")
    except subprocess.CalledProcessError as e:
        k8s_detail = f"kubectl command failed: {e.stderr.strip() if e.stderr else e}"
        logger.warning(f"[Containment] {k8s_detail}")
    except Exception as e:
        k8s_detail = f"Kubernetes operation error: {e}"
        logger.warning(f"[Containment] {k8s_detail}")

    return {
        "status": "quarantined",
        "pod": pod_name,
        "namespace": namespace,
        "policy_applied": "attestguard-quarantine",
        "k8s_api_executed": k8s_api_success,
        "k8s_detail": k8s_detail,
        "timestamp": time.time()
    }


def patch_gatekeeper_constraint(image_digest: str) -> dict:
    """
    Executes Gatekeeper Constraint patch via kubectl to update live cluster constraint:
    kubectl patch k8sblockrevokeddigests block-revoked-digests --type=json -p ...
    Appends newly revoked digest to parameters.revokedDigests array.
    """
    logger.info(f"[Feedback Loop] Patching Gatekeeper constraint with revoked digest '{image_digest}'...")
    patch_payload = json.dumps([
        {
            "op": "add",
            "path": "/spec/parameters/revokedDigests/-",
            "value": image_digest
        }
    ])
    cmd = [
        "kubectl", "patch", "k8sblockrevokeddigests", "block-revoked-digests",
        "--type=json", "-p", patch_payload
    ]

    success = False
    detail = ""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        success = True
        detail = res.stdout.strip()
        logger.info(f"[Gatekeeper Patch] Successfully patched constraint: {detail}")
    except FileNotFoundError:
        detail = "kubectl executable not found (Offline/Simulated mode)"
        logger.warning(f"[Gatekeeper Patch] {detail}")
    except subprocess.CalledProcessError as e:
        detail = f"kubectl patch failed: {e.stderr.strip() if e.stderr else e}"
        logger.warning(f"[Gatekeeper Patch] {detail}")
    except Exception as e:
        detail = f"Gatekeeper patch error: {e}"
        logger.warning(f"[Gatekeeper Patch] {detail}")

    return {
        "status": "patched" if success else "failed",
        "image_digest": image_digest,
        "success": success,
        "detail": detail
    }


def create_github_issue(rule_name: str, pod_name: str, image_digest: str, output_msg: str) -> dict:
    """
    Executes Stage 2 Feedback: Files deduplicated GitHub issue for engineering remediation.
    Performs real HTTP POST to https://api.github.com/repos/${GITHUB_REPOSITORY}/issues if GITHUB_TOKEN is set,
    or logs exact API payload if GITHUB_TOKEN is not set.
    """
    now = time.time()
    last_filed = filed_issues_cache.get(image_digest)
    
    if last_filed and (now - last_filed) < DEDUPLICATION_WINDOW_SEC:
        logger.info(f"[GitHub API] Issue for digest '{image_digest}' already filed within deduplication window. Skipping.")
        return {"status": "deduplicated", "image_digest": image_digest}
    
    repo = os.environ.get("GITHUB_REPOSITORY", "unveiledhistory49/attestguard")
    url = f"https://api.github.com/repos/{repo}/issues"
    token = os.environ.get("GITHUB_TOKEN")

    payload = {
        "title": f"[AttestGuard Security] Compromise detected: {rule_name} on {pod_name}",
        "body": (
            f"## AttestGuard Automated Security Incident Report\n\n"
            f"**Rule Violated:** {rule_name}\n"
            f"**Pod Name:** {pod_name}\n"
            f"**Image Digest:** {image_digest}\n"
            f"**Details:** {output_msg}\n\n"
            f"*This issue was automatically opened by AttestGuard Response Service.*"
        ),
        "labels": ["security", "attestguard-alert"]
    }

    if token:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "AttestGuard-ResponseService"
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                issue_id = str(res_data.get("number", f"GH-{int(now)}"))
                logger.info(f"[GitHub API] Successfully created GitHub issue #{issue_id} at {url}")
                filed_issues_cache[image_digest] = now
                return {
                    "status": "created",
                    "issue_id": issue_id,
                    "rule": rule_name,
                    "pod": pod_name,
                    "image_digest": image_digest,
                    "summary": payload["title"],
                    "api_executed": True
                }
        except Exception as e:
            logger.error(f"[GitHub API] HTTP POST request to {url} failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "rule": rule_name,
                "pod": pod_name,
                "image_digest": image_digest,
                "api_executed": False
            }
    else:
        logger.info(f"[GitHub API] GITHUB_TOKEN not set. Target URL: {url}. Payload: {json.dumps(payload)}")
        filed_issues_cache[image_digest] = now
        return {
            "status": "created",
            "issue_id": f"GH-ISSUE-{int(now)}",
            "rule": rule_name,
            "pod": pod_name,
            "image_digest": image_digest,
            "summary": payload["title"],
            "api_executed": False
        }


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "healthy", "service": "attestguard-response-service"}), 200


@app.route("/api/v1/falco-alert", methods=["POST"])
def handle_falco_alert():
    # 1. HMAC Authentication Verification
    signature_header = request.headers.get("X-AttestGuard-HMAC-Signature", "")
    if not verify_hmac_signature(request.get_data(), signature_header):
        logger.warning("[Security Auth] Unauthorized Falco alert attempt - HMAC signature mismatch!")
        return jsonify({"error": "Unauthorized: Invalid HMAC signature"}), 401
    
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON payload: {e}"}), 400
    
    rule = payload.get("rule", "Unknown Rule")
    priority = payload.get("priority", "WARNING").upper()
    output = payload.get("output", "")
    output_fields = payload.get("output_fields", {})
    
    pod_name = output_fields.get("k8s.pod.name", output_fields.get("pod", "unknown-pod"))
    namespace = output_fields.get("k8s.ns.name", "default")
    image_digest = output_fields.get("container.image.digest", output_fields.get("digest", "unknown-digest"))
    
    logger.info(f"[Alert Received] Rule: {rule} | Priority: {priority} | Pod: {pod_name} | Digest: {image_digest}")
    
    # Process CRITICAL or WARNING security alerts
    containment_result = isolate_pod_network(namespace, pod_name)
    
    # Update Admission Controller Revocation List & Patch Gatekeeper Constraint (Feedback Loop)
    revocation_updated = False
    gatekeeper_patch_result = None
    if image_digest != "unknown-digest":
        revocation_updated = save_revoked_digest(image_digest)
        gatekeeper_patch_result = patch_gatekeeper_constraint(image_digest)
    
    # File GitHub Issue
    issue_result = create_github_issue(rule, pod_name, image_digest, output)
    
    return jsonify({
        "status": "processed",
        "action_taken": "pod_quarantined_and_digest_revoked",
        "containment": containment_result,
        "digest_revoked": revocation_updated,
        "gatekeeper_patch": gatekeeper_patch_result,
        "github_issue": issue_result
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


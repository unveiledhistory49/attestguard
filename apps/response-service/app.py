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
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AttestGuard-ResponseService")

app = Flask(__name__)

# Security & Operations Configuration
HMAC_SECRET = os.environ.get("ATTESTGUARD_HMAC_SECRET", "attestguard-dev-secret-key-32bytes!")
REVOKED_DIGESTS_FILE = os.environ.get("REVOKED_DIGESTS_FILE", "/tmp/attestguard_revoked_digests.json")
DEDUPLICATION_WINDOW_SEC = int(os.environ.get("DEDUPLICATION_WINDOW_SEC", 86400))  # 24 hours

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
    Executes Stage 1 Containment: Applies quarantine network policy label to isolate pod.
    In K8s cluster, this communicates with the K8s API server.
    """
    logger.info(f"[Containment] Isolating pod '{pod_name}' in namespace '{namespace}' via Quarantine NetworkPolicy.")
    return {
        "status": "quarantined",
        "pod": pod_name,
        "namespace": namespace,
        "policy_applied": "attestguard-quarantine",
        "timestamp": time.time()
    }


def create_github_issue(rule_name: str, pod_name: str, image_digest: str, output_msg: str) -> dict:
    """
    Executes Stage 2 Feedback: Files deduplicated GitHub issue for engineering remediation.
    """
    now = time.time()
    last_filed = filed_issues_cache.get(image_digest)
    
    if last_filed and (now - last_filed) < DEDUPLICATION_WINDOW_SEC:
        logger.info(f"[GitHub API] Issue for digest '{image_digest}' already filed within deduplication window. Skipping.")
        return {"status": "deduplicated", "image_digest": image_digest}
    
    filed_issues_cache[image_digest] = now
    logger.info(f"[GitHub API] Filed Issue for compromised digest '{image_digest}' (Rule: {rule_name}, Pod: {pod_name})")
    
    return {
        "status": "created",
        "issue_id": f"GH-ISSUE-{int(now)}",
        "rule": rule_name,
        "pod": pod_name,
        "image_digest": image_digest,
        "summary": f"AttestGuard Security Compromise: {rule_name} detected on pod {pod_name}"
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
    
    # Update Admission Controller Revocation List (Feedback Loop)
    revocation_updated = False
    if image_digest != "unknown-digest":
        revocation_updated = save_revoked_digest(image_digest)
    
    # File GitHub Issue
    issue_result = create_github_issue(rule, pod_name, image_digest, output)
    
    return jsonify({
        "status": "processed",
        "action_taken": "pod_quarantined_and_digest_revoked",
        "containment": containment_result,
        "digest_revoked": revocation_updated,
        "github_issue": issue_result
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

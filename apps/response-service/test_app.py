#!/usr/bin/env python3
"""
Unit and Integration Tests for AttestGuard Response Service
"""

import os
import sys
import json
import hmac
import hashlib
import unittest

# Point to app module
sys.path.insert(0, os.path.dirname(__file__))

# Configure test environment secrets
os.environ["ATTESTGUARD_HMAC_SECRET"] = "test-secret-key-32bytes-attestguard"
os.environ["REVOKED_DIGESTS_FILE"] = "/tmp/test_revoked_digests.json"

from app import app, verify_hmac_signature, load_revoked_digests, HMAC_SECRET


class TestResponseService(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        if os.path.exists("/tmp/test_revoked_digests.json"):
            os.remove("/tmp/test_revoked_digests.json")

    def tearDown(self):
        if os.path.exists("/tmp/test_revoked_digests.json"):
            os.remove("/tmp/test_revoked_digests.json")

    def compute_hmac(self, data_bytes):
        return hmac.new(
            HMAC_SECRET.encode("utf-8"),
            data_bytes,
            hashlib.sha256
        ).hexdigest()

    def test_healthz(self):
        response = self.app.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "healthy")

    def test_unauthorized_missing_hmac(self):
        payload = {"rule": "AttestGuard Interactive Shell Spawned", "priority": "CRITICAL"}
        response = self.app.post("/api/v1/falco-alert", json=payload)
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn("Unauthorized", data["error"])

    def test_unauthorized_bad_hmac(self):
        payload = {"rule": "AttestGuard Interactive Shell Spawned", "priority": "CRITICAL"}
        headers = {"X-AttestGuard-HMAC-Signature": "invalid-hex-signature-12345"}
        response = self.app.post("/api/v1/falco-alert", json=payload, headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_authorized_alert_processing(self):
        payload = {
            "rule": "AttestGuard Interactive Shell Spawned",
            "priority": "CRITICAL",
            "output": "Interactive shell spawned in container pod-hardened-123",
            "output_fields": {
                "k8s.pod.name": "target-service-7f8d9b-x89zk",
                "k8s.ns.name": "production",
                "container.image.digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        sig = self.compute_hmac(body_bytes)
        headers = {
            "Content-Type": "application/json",
            "X-AttestGuard-HMAC-Signature": sig
        }

        response = self.app.post("/api/v1/falco-alert", data=body_bytes, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "processed")
        self.assertEqual(data["containment"]["status"], "quarantined")
        self.assertTrue(data["digest_revoked"])
        self.assertEqual(data["github_issue"]["status"], "created")

        # Verify digest persisted to revocation list
        revoked = load_revoked_digests()
        self.assertIn("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", revoked)

    def test_deduplicated_github_issue(self):
        payload = {
            "rule": "AttestGuard Package Manager Execution",
            "priority": "CRITICAL",
            "output": "Package manager executed inside container",
            "output_fields": {
                "k8s.pod.name": "target-service-pod-2",
                "container.image.digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            }
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        sig = self.compute_hmac(body_bytes)
        headers = {"Content-Type": "application/json", "X-AttestGuard-HMAC-Signature": sig}

        # First alert
        res1 = self.app.post("/api/v1/falco-alert", data=body_bytes, headers=headers)
        d1 = json.loads(res1.data)
        self.assertEqual(d1["github_issue"]["status"], "created")

        # Duplicate alert for same digest
        res2 = self.app.post("/api/v1/falco-alert", data=body_bytes, headers=headers)
        d2 = json.loads(res2.data)
        self.assertEqual(d2["github_issue"]["status"], "deduplicated")


if __name__ == "__main__":
    unittest.main()

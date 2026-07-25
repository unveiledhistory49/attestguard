#!/usr/bin/env python3
"""
Unit and Integration Tests for AttestGuard Response Service
Rule 8 & 6 Compliant
"""

import os
import sys
import json
import hmac
import hashlib
import unittest
import unittest.mock
import importlib

# Rule 8: Environment secret MUST be explicitly set before importing app.py
os.environ["ATTESTGUARD_HMAC_SECRET"] = "test-secret-key-32bytes-attestguard"
os.environ["REVOKED_DIGESTS_FILE"] = "/tmp/test_revoked_digests.json"

sys.path.insert(0, os.path.dirname(__file__))
from app import (
    app,
    verify_hmac_signature,
    load_revoked_digests,
    HMAC_SECRET,
    isolate_pod_network,
    patch_gatekeeper_constraint,
    create_github_issue,
    filed_issues_cache
)


class TestResponseService(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        if os.path.exists("/tmp/test_revoked_digests.json"):
            os.remove("/tmp/test_revoked_digests.json")
        filed_issues_cache.clear()

    def tearDown(self):
        if os.path.exists("/tmp/test_revoked_digests.json"):
            os.remove("/tmp/test_revoked_digests.json")
        filed_issues_cache.clear()

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

    def test_missing_secret_raises_fatal_error(self):
        """Rule 8: Verify that missing ATTESTGUARD_HMAC_SECRET fails loudly with ValueError."""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            import app as app_module
            with self.assertRaises(ValueError):
                importlib.reload(app_module)
        # Restore app with valid secret
        import app as app_module
        importlib.reload(app_module)

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

    @unittest.mock.patch("subprocess.run")
    def test_isolate_pod_network_subprocess_calls(self, mock_subprocess):
        """Audit #5: Assert isolate_pod_network performs expected kubectl label and apply commands."""
        mock_subprocess.return_value.stdout = "success"
        result = isolate_pod_network("production", "target-pod-123")
        
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["pod"], "target-pod-123")
        self.assertEqual(result["namespace"], "production")
        self.assertTrue(result["k8s_api_executed"])
        
        self.assertEqual(mock_subprocess.call_count, 2)
        call1 = mock_subprocess.call_args_list[0][0][0]
        call2 = mock_subprocess.call_args_list[1][0][0]
        
        self.assertEqual(call1, ["kubectl", "label", "pod", "target-pod-123", "-n", "production", "quarantine=true", "--overwrite"])
        self.assertEqual(call2[0:3], ["kubectl", "apply", "-f"])
        self.assertIn("quarantine-policy.yaml", call2[3])

    @unittest.mock.patch("subprocess.run")
    def test_patch_gatekeeper_constraint_subprocess_call(self, mock_subprocess):
        """Audit #6: Assert patch_gatekeeper_constraint executes kubectl patch with JSON payload."""
        mock_subprocess.return_value.stdout = "k8sblockrevokeddigests.constraints.gatekeeper.sh/block-revoked-digests patched"
        digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = patch_gatekeeper_constraint(digest)
        
        self.assertEqual(result["status"], "patched")
        self.assertEqual(result["image_digest"], digest)
        self.assertTrue(result["success"])
        
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        expected_payload = json.dumps([
            {"op": "add", "path": "/spec/parameters/revokedDigests/-", "value": digest}
        ])
        self.assertEqual(call_args, [
            "kubectl", "patch", "k8sblockrevokeddigests", "block-revoked-digests",
            "--type=json", "-p", expected_payload
        ])

    @unittest.mock.patch("urllib.request.urlopen")
    def test_create_github_issue_with_token(self, mock_urlopen):
        """Audit #7: Assert create_github_issue performs HTTP POST to GitHub REST API when token exists."""
        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = json.dumps({"number": 101}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        with unittest.mock.patch.dict(os.environ, {
            "GITHUB_TOKEN": "ghp_mocktoken12345",
            "GITHUB_REPOSITORY": "unveiledhistory49/attestguard"
        }):
            result = create_github_issue("RCE Detected", "pod-sec-1", "sha256:digest123", "Falco RCE details")
            
            self.assertEqual(result["status"], "created")
            self.assertEqual(result["issue_id"], "101")
            self.assertTrue(result["api_executed"])
            
            mock_urlopen.assert_called_once()
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.full_url, "https://api.github.com/repos/unveiledhistory49/attestguard/issues")
            self.assertEqual(req.headers.get("Authorization"), "Bearer ghp_mocktoken12345")
            self.assertEqual(req.headers.get("Accept"), "application/vnd.github+json")
            
            body = json.loads(req.data.decode("utf-8"))
            self.assertEqual(body["title"], "[AttestGuard Security] Compromise detected: RCE Detected on pod-sec-1")
            self.assertIn("sha256:digest123", body["body"])

    @unittest.mock.patch("app.logger.info")
    def test_create_github_issue_without_token(self, mock_log_info):
        """Audit #7: Assert create_github_issue logs exact payload when GITHUB_TOKEN is missing."""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            result = create_github_issue("RCE Detected", "pod-sec-2", "sha256:digest456", "Falco RCE details")
            
            self.assertEqual(result["status"], "created")
            self.assertFalse(result["api_executed"])
            self.assertIn("GH-ISSUE-", result["issue_id"])
            
            log_msgs = [call[0][0] for call in mock_log_info.call_args_list if len(call[0]) > 0]
            logged_payload = any("GITHUB_TOKEN not set" in msg and "sha256:digest456" in msg for msg in log_msgs)
            self.assertTrue(logged_payload)

    @unittest.mock.patch("subprocess.run")
    def test_authorized_alert_processing(self, mock_subprocess):
        """Integration Test: Full Falco alert webhook processing with containment, gatekeeper patch, and issue creation."""
        mock_subprocess.return_value.stdout = "success"

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
        self.assertIsNotNone(data["gatekeeper_patch"])
        self.assertEqual(data["gatekeeper_patch"]["status"], "patched")
        self.assertEqual(data["github_issue"]["status"], "created")

        # Verify digest persisted to revocation list
        revoked = load_revoked_digests()
        self.assertIn("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", revoked)

    @unittest.mock.patch("subprocess.run")
    def test_deduplicated_github_issue(self, mock_subprocess):
        """Integration Test: Verify issue deduplication across consecutive alerts for same digest."""
        mock_subprocess.return_value.stdout = "success"

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


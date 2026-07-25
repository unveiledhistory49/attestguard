#!/usr/bin/env python3
"""
Falco Rule Validator & Behavioral Syntax Test Suite for AttestGuard
Verifies rule structure, conditions, output fields, and priorities in attestguard_rules.yaml
"""

import os
import sys
import unittest

# Try loading yaml parser (ruamel.yaml, pyyaml, or simple string parser)
try:
    import yaml
except ImportError:
    yaml = None

RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "deploy", "falco", "rules", "attestguard_rules.yaml"
)

VALID_PRIORITIES = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"}

class TestFalcoRules(unittest.TestCase):

    def setUp(self):
        self.assertTrue(os.path.exists(RULES_FILE), f"Rules file missing: {RULES_FILE}")
        with open(RULES_FILE, "r") as f:
            self.content = f.read()

    def test_file_non_empty(self):
        self.assertGreater(len(self.content.strip()), 50, "Rules file is empty or too short")

    def test_required_attestguard_rules_present(self):
        required_rules = [
            "AttestGuard Interactive Shell Spawned",
            "AttestGuard Package Manager Execution",
            "AttestGuard K8s ServiceAccount Token Exfiltration Attempt",
            "AttestGuard Unauthorized Outbound Egress"
        ]
        for rule in required_rules:
            self.assertIn(rule, self.content, f"Required Falco rule missing: {rule}")

    def test_parsed_rules_structure(self):
        if yaml:
            data = yaml.safe_load(self.content)
            self.assertIsInstance(data, list, "Falco rules YAML root must be a list")
            for item in data:
                if "rule" in item:
                    rule_name = item["rule"]
                    self.assertIn("desc", item, f"Rule '{rule_name}' missing desc field")
                    self.assertIn("condition", item, f"Rule '{rule_name}' missing condition field")
                    self.assertIn("output", item, f"Rule '{rule_name}' missing output field")
                    self.assertIn("priority", item, f"Rule '{rule_name}' missing priority field")
                    self.assertIn(item["priority"].upper(), VALID_PRIORITIES, f"Rule '{rule_name}' has invalid priority: {item['priority']}")
                    self.assertIn("attestguard", item.get("tags", []), f"Rule '{rule_name}' missing 'attestguard' tag")
        else:
            # String fallback verification
            self.assertIn("priority: CRITICAL", self.content)
            self.assertIn("tags: [attestguard", self.content)

if __name__ == "__main__":
    unittest.main()

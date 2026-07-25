package k8spspnonroot

# True-Positive Test: Denies pod with root execution
test_violation_root_user {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "bad-root-pod"},
        "spec": {
          "containers": [
            {
              "name": "vulnerable-app",
              "image": "myregistry/app:v1.0.0",
              "securityContext": {
                "runAsUser": 0
              }
            }
          ]
        }
      }
    }
  }
  count(violation) == 1 with input as sample_input
}

# True-Negative Test: Allows compliant pod running as non-root
test_allow_non_root_user {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "good-pod"},
        "spec": {
          "containers": [
            {
              "name": "hardened-app",
              "image": "myregistry/app:v1.0.0",
              "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 65532
              }
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

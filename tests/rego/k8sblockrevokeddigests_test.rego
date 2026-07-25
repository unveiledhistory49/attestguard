package k8sblockrevokeddigests

# True-Positive Test: Denies container matching a dynamically revoked image digest
test_violation_revoked_digest {
  sample_input := {
    "parameters": {
      "revokedDigests": [
        "sha256:badc0de111111111111111111111111111111111111111111111111111111111"
      ]
    },
    "review": {
      "object": {
        "metadata": {"name": "compromised-pod"},
        "spec": {
          "containers": [
            {
              "name": "revoked-app",
              "image": "ghcr.io/org/target-service@sha256:badc0de111111111111111111111111111111111111111111111111111111111"
            }
          ]
        }
      }
    }
  }
  count(violation) == 1 with input as sample_input
}

# True-Negative Test: Allows clean container digest not in the revocation list
test_allow_clean_digest {
  sample_input := {
    "parameters": {
      "revokedDigests": [
        "sha256:badc0de111111111111111111111111111111111111111111111111111111111"
      ]
    },
    "review": {
      "object": {
        "metadata": {"name": "clean-pod"},
        "spec": {
          "containers": [
            {
              "name": "good-app",
              "image": "ghcr.io/org/target-service@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

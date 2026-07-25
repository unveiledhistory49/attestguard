package k8spspalwayspullimage

# True-Positive Test: Denies container using :latest tag
test_violation_latest_tag {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "latest-pod"},
        "spec": {
          "containers": [
            {
              "name": "unstable-app",
              "image": "ghcr.io/org/target-service:latest"
            }
          ]
        }
      }
    }
  }
  count(violation) == 1 with input as sample_input
}

# True-Negative Test: Allows container with explicit version tag or sha256 digest
test_allow_versioned_tag {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "pinned-pod"},
        "spec": {
          "containers": [
            {
              "name": "stable-app",
              "image": "ghcr.io/org/target-service:v1.2.3"
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

# True-Negative Test: Allows container with sha256 digest
test_allow_sha256_digest {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "digest-pod"},
        "spec": {
          "containers": [
            {
              "name": "immutable-app",
              "image": "ghcr.io/org/target-service@sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

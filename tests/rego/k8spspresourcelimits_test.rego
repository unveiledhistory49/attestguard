package k8spspresourcelimits

# True-Positive Test: Denies container missing resource limits
test_violation_missing_limits {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "unlimited-pod"},
        "spec": {
          "containers": [
            {
              "name": "greedy-app",
              "image": "myregistry/app:v1.0.0"
            }
          ]
        }
      }
    }
  }
  count(violation) >= 1 with input as sample_input
}

# True-Negative Test: Allows container with explicit CPU and memory limits
test_allow_configured_limits {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "bounded-pod"},
        "spec": {
          "containers": [
            {
              "name": "good-app",
              "image": "myregistry/app:v1.0.0",
              "resources": {
                "limits": {
                  "cpu": "500m",
                  "memory": "256Mi"
                }
              }
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

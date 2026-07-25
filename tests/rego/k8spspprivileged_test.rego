package k8spspprivileged

# True-Positive Test: Denies privileged container
test_violation_privileged {
  sample_input := {
    "review": {
      "object": {
        "metadata": {"name": "bad-privileged-pod"},
        "spec": {
          "containers": [
            {
              "name": "attacker-app",
              "image": "myregistry/app:v1.0.0",
              "securityContext": {
                "privileged": true
              }
            }
          ]
        }
      }
    }
  }
  count(violation) == 1 with input as sample_input
}

# True-Negative Test: Allows unprivileged container
test_allow_unprivileged {
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
                "privileged": false
              }
            }
          ]
        }
      }
    }
  }
  count(violation) == 0 with input as sample_input
}

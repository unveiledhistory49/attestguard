package k8spspprivileged

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  c_privileged(container)
  msg := sprintf("Privileged container '%v' is disallowed", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  c_privileged(container)
  msg := sprintf("Privileged initContainer '%v' is disallowed", [container.name])
}

c_privileged(container) {
  container.securityContext.privileged == true
}

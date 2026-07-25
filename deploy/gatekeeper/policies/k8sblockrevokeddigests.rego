package k8sblockrevokeddigests

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  revoked_digest := input.parameters.revokedDigests[_]
  contains(container.image, revoked_digest)
  msg := sprintf("Container '%v' uses image digest '%v' which has been dynamically revoked due to runtime compromise", [container.name, revoked_digest])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  revoked_digest := input.parameters.revokedDigests[_]
  contains(container.image, revoked_digest)
  msg := sprintf("InitContainer '%v' uses image digest '%v' which has been dynamically revoked due to runtime compromise", [container.name, revoked_digest])
}

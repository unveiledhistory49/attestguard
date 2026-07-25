package k8spspresourcelimits

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  missing_limits(container)
  msg := sprintf("Container '%v' must specify cpu and memory resource limits", [container.name])
}

missing_limits(container) {
  not container.resources.limits.cpu
}

missing_limits(container) {
  not container.resources.limits.memory
}

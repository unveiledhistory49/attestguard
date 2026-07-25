package k8spspnonroot

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not is_non_root(container, input.review.object.spec)
  msg := sprintf("Container '%v' must set runAsNonRoot to true or specify a non-zero runAsUser", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not is_non_root(container, input.review.object.spec)
  msg := sprintf("InitContainer '%v' must set runAsNonRoot to true or specify a non-zero runAsUser", [container.name])
}

is_non_root(container, pod_spec) {
  container.securityContext.runAsNonRoot == true
}

is_non_root(container, pod_spec) {
  container.securityContext.runAsUser > 0
}

is_non_root(container, pod_spec) {
  not container.securityContext.runAsNonRoot == false
  not container.securityContext.runAsUser == 0
  pod_spec.securityContext.runAsNonRoot == true
}

is_non_root(container, pod_spec) {
  not container.securityContext.runAsUser == 0
  pod_spec.securityContext.runAsUser > 0
}

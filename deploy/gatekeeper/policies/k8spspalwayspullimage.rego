package k8spspalwayspullimage

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  has_latest_tag(container.image)
  msg := sprintf("Container '%v' uses disallowed ':latest' image tag in image '%v'", [container.name, container.image])
}

has_latest_tag(image) {
  endswith(image, ":latest")
}

has_latest_tag(image) {
  not contains(image, ":")
  not contains(image, "@sha256:")
}

group "ci-images" {
  targets = ["rules-verifier", "final"]
}

target "ci-base" {
  context    = "."
  dockerfile = "docker/Dockerfile"
  cache-from = ["type=gha,scope=strixd-build"]
  output     = ["type=docker"]
}

target "rules-verifier" {
  inherits = ["ci-base"]
  target   = "rules-verifier"
  tags     = ["strixd-rules-verifier:ci"]
}

target "final" {
  inherits = ["ci-base"]
  target   = "final"
  tags     = ["strixd:ci"]
  args     = { LOCAL_ONLY = "1" }
  cache-to = ["type=gha,mode=max,scope=strixd-build"]
}

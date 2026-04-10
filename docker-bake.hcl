// This is set automatically when running in Github Actions
variable "CI" { default = "false" }
variable "ENCLAVE_EIF" { default = "" }

variable "IMAGES" {
  default = [
    "signer",
    "signer-with-enclave",
    "enclave",
  ]
}

target "docker-metadata-action" {}

target "meta-target" {
  matrix = { item = IMAGES }
  name   = "${item}-meta-target"

  context    = "."
  dockerfile = "docker/Dockerfile"
  target     = item
  args       = { ENCLAVE_EIF = ENCLAVE_EIF }

  // Default tags for local build. These will be overridden in CI.
  tags = [
    "nitro-enclave-signer/${item}:latest"
  ]
  // When building locally, load into docker
  output = CI ? [] : ["type=docker"]
}

group "default" {
  targets = ["signer"]
}

target "target" {
  matrix   = { item = IMAGES }
  name     = item
  inherits = ["${item}-meta-target", "docker-metadata-action"]
}

// This is set automatically when running in Github Actions
variable "CI" { default = "false" }
variable "ENCLAVE_EIF" { default = "" }

// Reproducible enclave build variables.
variable "SOURCE_DATE_EPOCH" { default = "0" }

// Enclave PCR measurements set from nitro-cli describe-eif output.
variable "ENCLAVE_PCR0" { default = "" }
variable "ENCLAVE_PCR1" { default = "" }
variable "ENCLAVE_PCR2" { default = "" }

target "docker-metadata-action" {}
variable "IMAGES" {
  default = [
    "signer",
    "signer-with-enclave",
  ]
}

target "meta-target" {
  matrix = { item = IMAGES }
  name   = "${item}-meta-target"

  context    = "."
  dockerfile = "docker/Dockerfile"
  target     = item

  contexts = {
    certs = "./docker/certs"
  }

  args = {
    ENCLAVE_EIF  = ENCLAVE_EIF
    ENCLAVE_PCR0 = ENCLAVE_PCR0
    ENCLAVE_PCR1 = ENCLAVE_PCR1
    ENCLAVE_PCR2 = ENCLAVE_PCR2
  }

  tags   = ["nitro-enclave-signer/${item}:latest"]
  output = CI ? [] : ["type=docker"]
}

target "target" {
  matrix   = { item = IMAGES }
  name     = item
  inherits = ["${item}-meta-target", "docker-metadata-action"]
}

group "default" {
  targets = ["signer"]
}

// Enclave uses a separate Dockerfile for reproducible builds.
target "enclave-meta-target" {
  context    = "."
  dockerfile = "docker/Dockerfile.enclave"
  target     = "enclave"

  contexts = {
    certs = "./docker/certs"
  }

  args = {
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
  }

  tags   = ["nitro-enclave-signer/enclave:latest"]
  // rewrite-timestamp requires BuildKit >= 0.13.0
  output = ["type=docker,rewrite-timestamp=true"]
}

target "enclave" {
  inherits = ["enclave-meta-target", "docker-metadata-action"]
}

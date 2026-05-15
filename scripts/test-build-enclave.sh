#!/usr/bin/env bash

# Verify that two clean enclave builds produce the same image ID.

set -eu

TAG="nitro-enclave-signer/enclave:repro-test"

build_enclave() {
    docker buildx bake \
        --provenance=false \
        --set "*.tags=${TAG}" \
        --load \
        enclave 2>&1
}

get_image_id() {
    docker inspect --format '{{.Id}}' "${TAG}"
}

echo "==> Build 1..."
build_enclave
ID1=$(get_image_id)
echo "    ID: ${ID1}"

echo "==> Pruning BuildKit cache..."
docker builder prune -af >/dev/null 2>&1

echo "==> Build 2..."
build_enclave
ID2=$(get_image_id)
echo "    ID: ${ID2}"

echo ""
if [ "${ID1}" = "${ID2}" ]; then
    echo "PASS: enclave image is reproducible"
    echo "  ${ID1}"
    docker rmi "${TAG}" >/dev/null 2>&1 || true
else
    echo "FAIL: enclave image is NOT reproducible"
    echo "  Build 1: ${ID1}"
    echo "  Build 2: ${ID2}"
    echo ""
    echo "Image retained for inspection: ${TAG}"
    exit 1
fi

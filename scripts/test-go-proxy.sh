#!/usr/bin/env bash
set -eu
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=SCRIPTDIR/test-harness.sh
source "$PROJECT_DIR/scripts/test-harness.sh"
wrapper="$PROJECT_DIR/docker/go-with-proxy.sh"
test -f "$wrapper" || exit 1
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

public_without_credentials() (
    unset CLOUDSMITH_USER CLOUDSMITH_TOKEN NETRC
    export GOPROXY=https://proxy.golang.org,direct
    sh "$wrapper" sh -eu -c 'test "$GOPROXY" = https://proxy.golang.org,direct && test -z "${NETRC:-}"'
)

cloudsmith_requires_credentials() (
    unset CLOUDSMITH_USER CLOUDSMITH_TOKEN
    export GOPROXY=https://golang.cloudsmith.io/circle/go-public/
    ! sh "$wrapper" touch "$fixture/unexpected-command" && test ! -e "$fixture/unexpected-command"
)

cloudsmith_requires_token() (
    export CLOUDSMITH_USER=test-user
    unset CLOUDSMITH_TOKEN
    export GOPROXY=https://golang.cloudsmith.io/circle/go-public/
    ! sh "$wrapper" touch "$fixture/unexpected-command" && test ! -e "$fixture/unexpected-command"
)

cloudsmith_cleans_credentials() (
    export CLOUDSMITH_USER=test-user CLOUDSMITH_TOKEN=test-token
    export GOPROXY=https://golang.cloudsmith.io/circle/go-public/
    export RESULT_FILE="$fixture/netrc-path"
    sh "$wrapper" sh -eu -c '
        test "$(cat "$NETRC")" = "machine golang.cloudsmith.io login test-user password test-token"
        test "$(ls -l "$NETRC" | cut -c 1-10)" = -rw-------
        printf "%s" "$NETRC" > "$RESULT_FILE"
    ' || return 1
    test -f "$RESULT_FILE" && test ! -e "$(cat "$RESULT_FILE")"
)

cloudsmith_preserves_failure_and_cleans() (
    export CLOUDSMITH_USER=test-user CLOUDSMITH_TOKEN=test-token
    export GOPROXY=https://golang.cloudsmith.io/circle/go-public/
    export RESULT_FILE="$fixture/failure-netrc-path"
    result=0
    sh "$wrapper" sh -eu -c 'printf "%s" "$NETRC" > "$RESULT_FILE"; exit 42' || result=$?
    test "$result" -eq 42 && test ! -e "$(cat "$RESULT_FILE")"
)

bake_forwards_proxy() (
    cd "$PROJECT_DIR" || return 1
    local expected="${1:-https://proxy.golang.org,direct}"
    unset GOPROXY CLOUDSMITH_USER CLOUDSMITH_TOKEN
    if [ "$#" -gt 0 ]; then
        export GOPROXY="$1"
    fi
    docker buildx bake --print signer-dev enclave signer-with-enclave > "$fixture/bake.json" || return 1
    python3 - "$fixture/bake.json" "$expected" <<'PYTHON'
import json
import sys

with open(sys.argv[1]) as source:
    targets = json.load(source)["target"]
assert set(targets) == {"signer-dev", "enclave", "signer-with-enclave"}
for name, target in targets.items():
    assert target["args"]["GOPROXY"] == sys.argv[2], name
PYTHON
)

check 'Public downloads need no Cloudsmith credentials.' public_without_credentials
check 'Cloudsmith rejects a missing username before executing the command.' cloudsmith_requires_credentials
check 'Cloudsmith rejects a missing token before executing the command.' cloudsmith_requires_token
check 'Cloudsmith credentials are private and removed after success.' cloudsmith_cleans_credentials
check 'A failed command retains its status and removes credentials.' cloudsmith_preserves_failure_and_cleans
if command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
    check 'Bake defaults all Go targets to the public proxy.' bake_forwards_proxy
    check 'Bake forwards an explicit proxy to every Go target.' bake_forwards_proxy \
        https://golang.cloudsmith.io/circle/go-public/
else
    skip_check 'Bake proxy propagation.' 'Docker Buildx is not installed.'
fi
exit "$failures"

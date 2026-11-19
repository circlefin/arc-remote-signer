#!/bin/sh
set -eu

case "${GOPROXY:-}" in
    *https://golang.cloudsmith.io/*)
        : "${CLOUDSMITH_USER:?CLOUDSMITH_USER is required for Cloudsmith}"
        : "${CLOUDSMITH_TOKEN:?CLOUDSMITH_TOKEN is required for Cloudsmith}"
        umask 077
        NETRC="$(mktemp)"
        export NETRC
        trap 'rm -f "$NETRC"' EXIT
        printf 'machine golang.cloudsmith.io login %s password %s\n' \
            "$CLOUDSMITH_USER" "$CLOUDSMITH_TOKEN" > "$NETRC"
        "$@"
        ;;
    *)
        exec "$@"
        ;;
esac

#!/usr/bin/env bash
# IMAGE=ghcr.io/jtr860830/judex:0.2.0 CONFIG=./config.yaml OUT=./out deploy/podman/run.sh
# Optional CA=/path/to/ca.pem; configure source.ca_file as /etc/judex/ca.pem.
set -euo pipefail
IMAGE=${IMAGE:-ghcr.io/jtr860830/judex:0.2.0}
CONFIG=${CONFIG:-./config.yaml}
OUT=${OUT:-./out}
# A bare relative path is otherwise interpreted as a named volume by Podman.
for name in CONFIG OUT CA; do
    value=${!name:-}
    if [[ -n $value && $value != /* && $value != ./* && $value != ../* ]]; then
        printf -v "$name" './%s' "$value"
    fi
done
args=(run --rm --read-only --security-opt no-new-privileges)
for name in HARBOR_PASSWORD NEUVECTOR_PASSWORD UPLOAD_TOKEN; do
    if [[ ${!name+x} ]]; then
        export "$name"
        args+=(-e "$name")
    fi
done
if [[ -n ${CA:-} ]]; then
    args+=(-v "$CA":/etc/judex/ca.pem:ro,Z)
fi
exec podman "${args[@]}" \
    -v "$CONFIG":/etc/judex/config.yaml:ro,Z \
    -v "$OUT":/var/lib/judex/reports:Z "$IMAGE" "$@"

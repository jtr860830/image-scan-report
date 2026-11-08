#!/usr/bin/env bash
# IMAGE=ghcr.io/jtr860830/judex:1.0.0 CONFIG=./config.yaml OUT=./out deploy/podman/run.sh
# Optional CA=/path/to/ca.pem; configure source.ca_file as /etc/report/ca.pem.
set -euo pipefail
IMAGE=${IMAGE:-ghcr.io/jtr860830/judex:1.0.0}
CONFIG=${CONFIG:-./config.yaml}
OUT=${OUT:-./out}
args=(run --rm --read-only --security-opt no-new-privileges)
for name in HARBOR_PASSWORD NEUVECTOR_PASSWORD UPLOAD_TOKEN; do
    if [[ ${!name+x} ]]; then
        export "$name"
        args+=(-e "$name")
    fi
done
if [[ -n ${CA:-} ]]; then
    args+=(-v "$CA":/etc/report/ca.pem:ro,Z)
fi
exec podman "${args[@]}" \
    -v "$CONFIG":/etc/report/config.yaml:ro,Z \
    -v "$OUT":/output:Z "$IMAGE" "$@"

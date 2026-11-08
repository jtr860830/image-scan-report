# Container installation

The release image is `ghcr.io/jtr860830/judex:<ver>`. Replace `<ver>` with
an available release tag. Build a development image from the repository root:

```sh
podman build -t judex:dev -f Containerfile .
```

The builder uses Rust 1.99 on Debian 13 (trixie); runtime uses
`gcr.io/distroless/cc-debian13:nonroot`, with UID/GID 65532.
The image contains the binary, its embedded fonts, templates, strings and default
theme, and LICENSE plus THIRD_PARTY_NOTICES.md in `/usr/share/doc/judex/`.

## Run

Create an output directory writable by container UID 65532. On rootless Podman,
`podman unshare chown 65532:65532 ./out` can assign the mapped owner.
Configure output paths as `/output` and all input paths as container paths.
From a checkout, run the wrapper (defaults: `CONFIG=./config.yaml`, `OUT=./out`):

```sh
IMAGE=judex:dev CONFIG=./config.yaml OUT=./out deploy/podman/run.sh
```

The equivalent raw command for Harbor is:

```sh
podman run --rm --read-only --security-opt no-new-privileges \
  -v ./config.yaml:/etc/report/config.yaml:ro,Z \
  -v ./out:/output:Z -e HARBOR_PASSWORD judex:dev
```

The default command is `run --config /etc/report/config.yaml`. To validate first:

```sh
IMAGE=judex:dev deploy/podman/run.sh check --config /etc/report/config.yaml
```

Export secrets on the host and pass their names using `-e HARBOR_PASSWORD`,
`-e NEUVECTOR_PASSWORD`, or `-e UPLOAD_TOKEN`. The wrapper passes each of these
only when set; configuration must reference the matching environment variable.
Avoid putting secrets into the image or command arguments.

## Mounts

| Container path | Purpose |
| --- | --- |
| `/etc/report/config.yaml` | Required read-only configuration mount |
| `/etc/report/ca.pem` | Optional read-only PEM CA bundle; set `source.ca_file` to this path |
| `/etc/report/logo.png` | Optional read-only logo; set `report.logo` to this path |
| `/fixtures` | Example read-only scanner input directory; set `source.path` accordingly |
| `/output` | Writable report destination; set filesystem output `path` here |

Set `CA=./ca.pem` for the wrapper to mount the CA at `/etc/report/ca.pem`.
For a logo, add `-v ./logo.png:/etc/report/logo.png:ro,Z` to the raw command.
For file sources, add `-v ./fixtures:/fixtures:ro,Z` and configure
`source.path: /fixtures/trivy`. Custom themes also require a read-only mount
and a corresponding `theme.path` in the configuration.
The `:Z` suffix sets a private SELinux label for Podman bind mounts.

A read-only root filesystem works because the binary writes only to `/output`
when configured as above. All other mounted inputs can remain read-only.

## Air-gap transfer

On a connected host, pull the release and save it; replace `<ver>` throughout:

```sh
podman pull ghcr.io/jtr860830/judex:<ver>
podman save -o judex-<ver>.tar ghcr.io/jtr860830/judex:<ver>
```

Transfer the tar file to the isolated host, then load and run it:

```sh
podman load -i judex-<ver>.tar
IMAGE=ghcr.io/jtr860830/judex:<ver> deploy/podman/run.sh
```

File-based scans work offline; API sources and HTTP outputs still need access
to their configured services.

## Resources and troubleshooting

Memory use is about 0.8 GB plus 70 MB per 1,000 findings; the Kubernetes examples request 1 GiB and limit 4 GiB (about 45,000 findings).
Allow sufficient output disk space for both PDF and JSON when enabled.

Distroless has no shell; a `:debug-nonroot` image is not provided. Use `podman cp`
to retrieve artifacts from a stopped container, or run the binary locally to
investigate configuration and rendering. Use `judex:dev --version` through
`podman run --rm judex:dev --version` to inspect the embedded product version;
OCI version and revision labels describe the image build separately.

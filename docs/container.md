# Container installation

The release image is `ghcr.io/jtr860830/judex:<ver>`. Replace `<ver>` with
an available release tag.

## Local build

Build a development image from the repository root:

```sh
podman build -t judex:dev -f Containerfile .
```

Use a podman machine with at least 8 GiB; the release build OOM-kills under 2 GiB.

The builder uses Rust 1.99 on Debian 13 (trixie); runtime uses
`gcr.io/distroless/cc-debian13:nonroot`, with UID/GID 65532.
The image contains the binary, its embedded fonts, templates, strings and default
theme, and LICENSE plus THIRD_PARTY_NOTICES.md in `/usr/share/doc/judex/`.

## Run

Create an output directory writable by container UID 65532. On rootless Podman,
`podman unshare chown 65532:65532 ./out` can assign the mapped owner.
Configure output paths as `/var/lib/judex/reports` and all input paths as container paths.
From a checkout, run the wrapper (defaults: `CONFIG=./config.yaml`, `OUT=./out`):

```sh
IMAGE=judex:dev CONFIG=./config.yaml OUT=./out deploy/podman/run.sh
```

The equivalent raw command for Harbor is:

```sh
podman run --rm --read-only --security-opt no-new-privileges \
  -v ./config.yaml:/etc/judex/config.yaml:ro,Z \
  -v ./out:/var/lib/judex/reports:Z -e HARBOR_PASSWORD judex:dev
```

To validate first:

```sh
IMAGE=judex:dev deploy/podman/run.sh check --config /etc/judex/config.yaml
```

Export secrets on the host and pass their names using `-e HARBOR_PASSWORD`,
`-e NEUVECTOR_PASSWORD`, or `-e UPLOAD_TOKEN`. The wrapper passes each of these
only when set; configuration must reference the matching environment variable.
Avoid putting secrets into the image or command arguments.

## Mounts

| Container path | Purpose |
| --- | --- |
| `/etc/judex/config.yaml` | Required read-only configuration mount |
| `/etc/judex/ca.pem` | Optional read-only PEM CA bundle; set `source.ca_file` to this path |
| `/etc/judex/logo.png` | Optional read-only logo; set `report.logo` to this path |
| `/var/lib/judex/scans` | Example read-only scanner input directory; set `source.path` accordingly |
| `/var/lib/judex/reports` | Writable report destination; set filesystem output `path` here |

Set `CA=./ca.pem` for the wrapper to mount the CA at `/etc/judex/ca.pem`.
For a logo, add `-v ./logo.png:/etc/judex/logo.png:ro,Z` to the raw command.
For file sources, add `-v ./tests/fixtures:/var/lib/judex/scans:ro,Z` and configure
`source.path: /var/lib/judex/scans/trivy`. Mount external themes read-only and select them with `theme.path` or
`JUDEX_THEME_DIR`, or build them into an edition image as below.
The `:Z` suffix sets a private SELinux label for Podman bind mounts.

A read-only root filesystem works because the binary writes only to `/var/lib/judex/reports`
when configured as above. All other mounted inputs can remain read-only.

## Environment

| Variable | Purpose |
| --- | --- |
| `JUDEX_CONFIG` | Configuration path; see [Configuration reference](../README.md#configuration-reference) |
| `JUDEX_THEME_DIR` | Theme directory; see [Theme](../README.md#theme) |
| `RUST_LOG` | Log filter |
| `HARBOR_PASSWORD` | Harbor password when referenced by the configuration |
| `NEUVECTOR_PASSWORD` | NeuVector password when referenced by the configuration |
| `UPLOAD_TOKEN` | Upload token when referenced by the configuration |

Pass variables with `-e` in raw commands. The wrapper passes only the three
secret variables above; pass other variables explicitly in raw commands.
See the README for [configuration lookup](../README.md#configuration-reference) and
[theme selection and product identity](../README.md#theme).

## Building an edition image

Replace `<ver>` with a release tag and `<edition>` with the edition name:

```dockerfile
FROM ghcr.io/jtr860830/judex:<ver>
COPY theme/ /usr/share/<edition>/theme/
ENV JUDEX_THEME_DIR=/usr/share/<edition>/theme
```

Override the inherited OCI labels `org.opencontainers.image.source`,
`org.opencontainers.image.description`, and `org.opencontainers.image.title`
so the edition does not advertise upstream metadata.

Set `[product] name` in `theme.toml` to name the edition; see
[Theme](../README.md#theme) for selection and identity behaviour.

## Air-gap transfer

On a connected host, pull the release and save it; replace `<ver>` throughout:

```sh
podman pull ghcr.io/jtr860830/judex:<ver>
podman save -o judex-<ver>.tar ghcr.io/jtr860830/judex:<ver>
sha256sum judex-<ver>.tar > IMAGE-SHA256SUMS
```

Pull on a host matching the destination architecture; this saves that platform's
image. Repeat for the other platform if needed. Transfer the tar file and
IMAGE-SHA256SUMS to the isolated host, then verify, load and run it:

```sh
sha256sum -c IMAGE-SHA256SUMS
podman load -i judex-<ver>.tar
IMAGE=ghcr.io/jtr860830/judex:<ver> deploy/podman/run.sh
```

File-based scans work offline; API sources and HTTP outputs still need access
to their configured services.

## Resources

Memory use is about 0.8 GB plus 70 MB per 1,000 findings; see the
[measurements and derivation](development.md#rendering-performance-measured-2026-11-08-release-build-apple-silicon-median-of-three).
Allow sufficient output disk space for both PDF and JSON when enabled.

## Troubleshooting

Distroless has no shell, and a `:debug-nonroot` variant of this image is not
provided. Reports land in the `/var/lib/judex/reports` mount, so nothing needs to be copied
out of the container; to investigate configuration or rendering problems, run
the same binary locally with the same configuration file. `podman run --rm
judex:dev --version` prints the [product display](../README.md#theme); the OCI `version` and
`revision` labels describe the image build separately.

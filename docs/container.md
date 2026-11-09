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

The default command is `run`; it finds `/etc/judex/config.yaml`. To validate first:

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
| `JUDEX_CONFIG` | First configuration candidate when `--config` is omitted |
| `JUDEX_THEME_DIR` | Theme directory, after `theme.path` and before the embedded default |
| `RUST_LOG` | Log filter |
| `HARBOR_PASSWORD` | Harbor password when referenced by the configuration |
| `NEUVECTOR_PASSWORD` | NeuVector password when referenced by the configuration |
| `UPLOAD_TOKEN` | Upload token when referenced by the configuration |

Pass variables with `-e` in raw commands. The wrapper passes only the three
secret variables above; pass other variables explicitly in raw commands.
A set `JUDEX_THEME_DIR` must be non-empty and contain a valid `theme.toml`.

## Building an edition image

Replace `<ver>` with a release tag and `<edition>` with the edition name:

```dockerfile
FROM ghcr.io/jtr860830/judex:<ver>
COPY theme/ /usr/share/<edition>/theme/
ENV JUDEX_THEME_DIR=/usr/share/<edition>/theme
```

Configuration files then need no `theme:` block. An explicit `theme.path`
overrides the environment theme. Set `[product] name` in `theme.toml` to name
the edition; `--version` displays `<name> <ver> (judex)`. If the environment
theme is invalid, `--version` prints the upstream identity with one stderr
warning and exits 0; `run`, `check`, and `render-data` exit 2 when selecting
that invalid theme.

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

Distroless has no shell, and a `:debug-nonroot` variant of this image is not
provided. Reports land in the `/var/lib/judex/reports` mount, so nothing needs to be copied
out of the container; to investigate configuration or rendering problems, run
the same binary locally with the same configuration file. `podman run --rm
judex:dev --version` prints the theme-derived product display; the OCI `version` and
`revision` labels describe the image build separately.

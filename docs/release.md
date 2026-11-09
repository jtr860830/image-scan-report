# Release and rename guide

## Cutting a release

1. Optionally run `gh workflow run release.yml --ref main` after the workflow
   exists on the default branch. Dispatch pushes only
   `ghcr.io/jtr860830/judex:sha-<7>` (the seven-character commit SHA), creates no
   GitHub release and leaves native archives as workflow artifacts. Inspect both
   platforms in the manifest.
2. Bump `[package].version` in Cargo.toml and the matching package entry in
   Cargo.lock together. Update the image tags in deploy/k8s/job.yaml and
   deploy/k8s/cronjob.yaml and the `IMAGE` default in deploy/podman/run.sh.
3. Rename `## [Unreleased]` in CHANGELOG.md to `## [X.Y.Z] - YYYY-MM-DD`, add a
   fresh empty `## [Unreleased]`, and update the compare links at the bottom.
4. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
   `cargo test --offline`; see [development checks](development.md).
5. Commit the reviewed files and tag only a CI-green commit: the release
   workflow does not wait for CI. The signed tag must equal the Cargo version,
   prefixed with `v`; the workflow also requires the matching dated changelog
   heading before any build or publication.

   ```sh
   git tag -s vX.Y.Z -m 'Release X.Y.Z'
   git push origin vX.Y.Z
   ```

6. Review the assets and notes in the workflow's draft release (a pre-release
   for RC tags), then publish it by hand. For a stable release, run:

   ```sh
   gh release edit vX.Y.Z --draft=false --latest
   ```

   For an RC, publish with `--draft=false --latest=false` instead.

Only stable versions (without a `-`) update the image's `latest` tag; release
candidates never move `latest`. Deleting a tag or release is a manual step that
needs the owner's explicit decision.

## Assets

The release workflow builds natively on ubuntu-24.04 (x86_64-unknown-linux-gnu)
and ubuntu-24.04-arm (aarch64-unknown-linux-gnu). It installs the toolchain from
rust-toolchain.toml and runs `cargo build --release --locked`; no cross compiler
or emulation is involved. The two `judex-vX.Y.Z-<target>.tar.gz` archives contain
a top-level `judex-vX.Y.Z-<target>/` directory containing the binary, LICENSE,
THIRD_PARTY_NOTICES.md, README.md, docs/container.md, OFL texts in licenses/fonts/,
all example YAML configs in examples/, and the Podman wrapper run.sh for offline
use. Per-target checksums are merged into one SHA256SUMS; the release has these
three assets and the matching CHANGELOG section.

Verify downloads from their directory:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Native binaries require glibc >= 2.39 (built on ubuntu-24.04). Use the container
image on hosts with older glibc.

Native image builds export digests; a manifest job combines both architectures
at `ghcr.io/jtr860830/judex:X.Y.Z`, then verifies both architectures. Images
publish before the draft is reviewed. After the first GHCR push, check in the
package settings that the package is public and linked to the repository.

## Air-gap bundle

Download the target tarball and SHA256SUMS on a connected machine, transfer them
together, and verify them on the isolated host as described in [Assets](#assets)
before extracting the tarball. See [air-gap image transfer](container.md#air-gap-transfer)
for image archives.

## Rename procedure

Keep the library crate name `image_scan_report`. Update these product surfaces:

1. `[package] name` in Cargo.toml, the self dev-dependency's `package` value and
   the matching Cargo.lock package entry.
2. `PRODUCT_NAME` in src/main.rs (the only source/template/string literal).
3. `BIN` and `IMAGE_NAME` in .github/workflows/release.yml, the single workflow
   naming point for archives and images.
4. The build binary name and COPY source, documentation, destination, and
   ENTRYPOINT paths in Containerfile.
5. `judex:ci` and its version-output assertion in .github/workflows/ci.yml.
6. Image references in deploy/k8s/*.yaml and deploy/podman/run.sh.
7. `[product].name` in assets/themes/default/theme.toml: this intentional branding
   literal is checked separately by the naming guard.
8. All of tests/: `cargo_bin_cmd!("judex")` calls, the image constant in
   tests/deploy_manifests.rs, and tests/snapshots/*.snap.
9. Product references in deploy/examples/ and user-facing README/docs examples.

Environment variable names (`<NAME>_CONFIG`, `<NAME>_THEME_DIR`) and default
configuration directories (`/etc/<name>` and the XDG `<name>` subdirectory) are
derived from `PRODUCT_NAME` in src/main.rs. Re-check these names and the
`/var/lib/<name>` report directory in Containerfile, deploy files and docs
after a rename.

From the repository root, this exact grep lists the naming surfaces:

```sh
grep -rn -i 'judex' Cargo.toml Cargo.lock src/ assets/templates/ assets/strings/ assets/themes/default/theme.toml Containerfile .github/workflows/release.yml .github/workflows/ci.yml deploy/k8s/ deploy/podman/run.sh tests/ deploy/examples/ README.md docs/
```

For example, update the image repository without introducing kustomization:

```sh
sed -i 's|ghcr.io/jtr860830/judex:|ghcr.io/jtr860830/NEW_NAME:|g' deploy/k8s/*.yaml deploy/podman/run.sh
```

Regenerate [third-party notices](development.md#third-party-notices) and run
`cargo test` after the rename.

`tests/naming_single_source.rs::product_name_appears_only_in_known_places`
reads the package name dynamically, rejects new literals in src/, assets/templates/ and
assets/strings/, and checks the default theme branding. The theme is an intentional
additional name surface; release/deployment configuration is reviewed separately.

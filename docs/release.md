# Release and rename guide

## Cutting a release

1. Bump `[package].version` in Cargo.toml and the judex package version in
   Cargo.lock together. Keep the Kubernetes image tags in deploy/k8s/*.yaml and
   deploy/podman/run.sh (including its default image tag) and version examples in README/docs aligned.
2. Review CHANGELOG.md and replace `unreleased` in the version heading with the
   release date (YYYY-MM-DD). Run the checks in [development.md](development.md).
3. Commit the reviewed files, then sign and push the tag:

   ```sh
   git tag -s vX.Y.Z -m 'Release X.Y.Z'
   git push origin vX.Y.Z
   ```

The release workflow builds natively on ubuntu-24.04 (x86_64-unknown-linux-gnu)
and ubuntu-24.04-arm (aarch64-unknown-linux-gnu). It installs the toolchain from
rust-toolchain.toml and runs `cargo build --release --locked`; no cross compiler
or emulation is involved. The two `judex-vX.Y.Z-<target>.tar.gz` archives contain
a top-level `judex-vX.Y.Z-<target>/` directory containing the binary, LICENSE, THIRD_PARTY_NOTICES.md, README.md, docs/container.md, OFL texts in licenses/fonts/, all example YAML
configs in examples/, and the Podman wrapper run.sh for offline use.
Per-target checksums are merged into one SHA256SUMS. The workflow creates a
**draft** GitHub release with those three assets and the matching CHANGELOG
section. Delete a stale draft before re-running the release job. Review the assets and notes, then publish the draft manually.

Native image builds export digests; a manifest job combines both architectures
at `ghcr.io/jtr860830/judex:X.Y.Z`, then verifies both architectures. Only stable
versions (without a `-`) update `:latest`; release candidates never move it.
Images publish before the draft is reviewed. After the first GHCR push, check in the
package settings that the package is public and linked to the repository.

Native binaries require glibc >= 2.39 (built on ubuntu-24.04). Use the container
image on hosts with older glibc. SHA256SUMS is checkable with `sha256sum -c
SHA256SUMS` from the download directory.

## Dispatch dry-run

`workflow_dispatch` is available only once release.yml exists on the default
branch. Use this order:

1. Merge the PR, then run `gh workflow run release.yml --ref main`.
   Dispatch publishes only `ghcr.io/jtr860830/judex:sha-<7>` (the seven-character
   commit SHA), never `:latest`, and creates no GitHub release. Native archives
   remain workflow artifacts. Inspect both platforms in the manifest.
2. After verification, either leave the test image or delete both its SHA tag
   and the untagged per-architecture and attestation manifests it references
   from the GHCR package versions page.
3. Date the CHANGELOG section, bump nothing else, and commit the change.
4. Tag only a CI-green commit: the release workflow does not wait for CI.

   ```sh
   git tag -s vX.Y.Z -m 'Release X.Y.Z'
   git push origin vX.Y.Z
   ```

The version job requires an exactly matching dated CHANGELOG heading before any
build or publication. RC tags produce a draft pre-release; stable tags produce a
draft release. Review and publish the draft manually.

## Air-gap bundle

On a connected machine, download both tarballs and SHA256SUMS from the release
(or just the target tarball when using `--ignore-missing`), then:

```sh
sha256sum -c SHA256SUMS --ignore-missing
podman pull ghcr.io/jtr860830/judex:0.1.0
podman save -o judex-image.tar ghcr.io/jtr860830/judex:0.1.0
sha256sum judex-image.tar > IMAGE-SHA256SUMS
```

Pull on a host matching the destination architecture; this saves that platform's
image. Repeat for the other platform if needed. Transfer the image archive,
IMAGE-SHA256SUMS, native tarball and SHA256SUMS together. On the isolated host:

```sh
sha256sum -c IMAGE-SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
podman load -i judex-image.tar
# Or extract the matching native tarball and put its executable on PATH.
```

Use `sha256sum -c SHA256SUMS` without `--ignore-missing` when both release
archives are present. See [container.md](container.md) for mounts and invocation.

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
7. `[product].name` in themes/default/theme.toml: this intentional branding
   literal is checked separately by the naming guard.
8. All of tests/: `cargo_bin_cmd!("judex")` calls, the image constant in
   tests/deploy_manifests.rs, and tests/snapshots/*.snap.
9. Product references in examples/ and user-facing README/docs examples.

From the repository root, this exact grep lists the naming surfaces:

```sh
grep -rn -i 'judex' Cargo.toml Cargo.lock src/ templates/ strings/ themes/default/theme.toml Containerfile .github/workflows/release.yml .github/workflows/ci.yml deploy/k8s/ deploy/podman/run.sh tests/ examples/ README.md docs/
```

For example, update the image repository without introducing kustomization:

```sh
sed -i 's|ghcr.io/jtr860830/judex:|ghcr.io/jtr860830/NEW_NAME:|g' deploy/k8s/*.yaml deploy/podman/run.sh
```

Regenerate notices and run the tests after the rename:

```sh
cargo about generate --config about.toml about.hbs -o THIRD_PARTY_NOTICES.md
cargo test
```

`tests/naming_single_source.rs::product_name_appears_only_in_known_places`
reads the package name dynamically, rejects new literals in src/, templates/ and
strings/, and checks the default theme branding. The theme is an intentional
additional name surface; release/deployment configuration is reviewed separately.

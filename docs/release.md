# Release and rename guide

## Cutting a release

1. Bump `[package].version` in Cargo.toml and the judex package version in
   Cargo.lock together. Keep the Kubernetes image tags in deploy/k8s/*.yaml and
   deploy/podman/run.sh (including its default image tag) and version examples in README/docs aligned. The current candidate is 1.0.0-rc.1;
   bump to 1.0.0 for the stable release.
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
a top-level `judex-vX.Y.Z-<target>/` directory containing the binary, LICENSE, THIRD_PARTY_NOTICES.md, README.md and docs/container.md.
Per-target checksums are merged into one SHA256SUMS. The workflow creates a
**draft** GitHub release with those three assets and the matching CHANGELOG
section. Delete a stale draft before re-running the release job. Review the assets and notes, then publish the draft manually.

Native image builds export digests; a manifest job combines both architectures
at `ghcr.io/jtr860830/judex:X.Y.Z`, then verifies both architectures. Only stable
versions (without a `-`) update `:latest`; release candidates never move it.
Images publish before the draft is reviewed. After the first GHCR push, make the
package public and link it to the repository in the package settings.

Native binaries require glibc >= 2.39 (built on ubuntu-24.04). Use the container
image on hosts with older glibc. SHA256SUMS is checkable with `sha256sum -c
SHA256SUMS` from the download directory.

## Dispatch dry-run

Run Release with workflow_dispatch on the branch. Leave `ref_tag` empty to use
the seven-character commit SHA as the build version, or set it to a version label
for archive naming. OCI VERSION is always `sha-<seven-character-SHA>` on dispatch. This input labels the build; it does not check
out another ref. Dispatch publishes only `:sha-<seven-character-SHA>`, never
`:latest`, and creates no GitHub release when dispatched on any ref. Native
binary archives remain available as workflow artifacts.

The release job requires `startsWith(github.ref, 'refs/tags/v')` and a push
event, so dispatch cannot create a release. Dispatch on the branch for testing. Controller validation is pending: this sandbox
has no network and has not run the hosted workflow. The controller should run:

```sh
podman run --rm ghcr.io/jtr860830/judex:sha-<short> --version
```

Inspect both platforms in the manifest and optionally delete the test tag after
verification. Record the hosted run URL and result here when available.

## Air-gap bundle

On a connected machine, download both tarballs and SHA256SUMS from the release
(or just the target tarball when using `--ignore-missing`), then:

```sh
sha256sum -c SHA256SUMS --ignore-missing
podman pull ghcr.io/jtr860830/judex:1.0.0-rc.1
podman save -o judex-image.tar ghcr.io/jtr860830/judex:1.0.0-rc.1
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
4. Both `ARG BIN` defaults and the destination/ENTRYPOINT paths in Containerfile.
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

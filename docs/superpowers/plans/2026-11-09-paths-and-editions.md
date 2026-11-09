# Standard Paths and Edition Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make judex follow FHS inside the image and XDG on a host (#10), let an edition image select its theme through the environment (#12), and let the edition's product name reach `--version`, `check` and the HTTP `User-Agent` (#13).

**Architecture:** `main.rs` remains the single place that knows the upstream product name; it derives the environment variable names from it and hands the process environment to the library as data (a `Runtime` value), so the naming guard keeps passing. Theme resolution becomes a three-step precedence (configuration → environment → embedded default) in `render::theme`, and `ProductInfo` is built from the resolved theme instead of from the binary alone. Container paths move to `/etc/judex`, `/var/lib/judex/{reports,scans}`; the deploy examples, CI smoke job and documentation follow.

**Tech Stack:** Rust 2024, clap 4 (derive), serde, ureq; Containerfile on distroless; Kubernetes/Podman examples.

**Spec:** GitHub issues #10, #12, #13, read together with `docs/superpowers/specs/2026-11-07-product-redesign-design.md` (white-label upstream, edition = `FROM upstream` + theme directory).

## Global Constraints

- The literal upstream name appears in `src/`, `assets/templates/`, `assets/strings/` only in `src/main.rs` (`tests/naming_single_source.rs`). Environment variable names and default directories that contain the name are therefore *derived in `main.rs`* and passed down as values; library code never spells them.
- Secrets come only from the environment and are never logged; nothing in this plan adds logging of request heads.
- British spelling in code comments and docs; Google Rust Style Guide; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --offline` stay clean after every task.
- `docs/superpowers/**` plans and specs are historical records: this file is appended with checkmarks only, never rewritten.
- Breaking changes are allowed (0.x) and listed in `CHANGELOG.md` under `[Unreleased]` with the old → new mapping; no compatibility shim for old paths beyond the error message in Task 3.
- Exit codes are unchanged: configuration and theme failures exit 2.

## Decisions taken in this plan (my calls — review these first)

| Topic | Decision |
|---|---|
| Configuration directory in the image | `/etc/judex/` holding `config.yaml`, `ca.pem`, `logo.png` |
| Output directory | `/var/lib/judex/reports` (`WORKDIR` and `VOLUME`); file-source example mount `/var/lib/judex/scans` |
| Host configuration lookup | `--config` → `$<NAME>_CONFIG` → `$XDG_CONFIG_HOME/<name>/config.yaml` (default `~/.config/<name>/config.yaml`) → `/etc/<name>/config.yaml`; the first existing file wins; none found is a configuration error listing every candidate, and if `/etc/report/config.yaml` exists the message adds "configuration moved to /etc/<name>/config.yaml in 0.2.0" |
| Theme environment variable | `<NAME>_THEME_DIR` (`JUDEX_THEME_DIR` for the upstream binary). Precedence: `theme.path` in the configuration → the variable → embedded default. A set variable that does not resolve to a valid theme is an error, never a silent fallback |
| Product display | default theme: `judex 0.2.0`; edition theme: `Arishem 0.2.0 (judex)`. Printed by `version`, `--version`/`-V`, and `check` |
| `check` tail | `…; product: Arishem 0.2.0 (judex); theme: env` where the theme source is one of `config`, `env`, `default` |
| User-Agent | default theme `judex/0.2.0`; edition `Arishem/0.2.0 judex/0.2.0`. The stale `image-scan-report/<ver>` constant is removed |
| `--version` when the theme variable is invalid | print the upstream display and a one-line warning on stderr; do not fail a version query |
| Kubernetes namespace and labels | `image-scan-report` → `judex` (same change class as the paths, one breaking release) |
| Version bump | not in this plan; `Cargo.toml` is bumped to 0.2.0 when the release is cut, as `docs/release.md` describes |

## Review Focus

1. `theme.path` set in the configuration **and** `JUDEX_THEME_DIR` set to a different directory: configuration wins and `check` says `theme: config`. Test in Task 1.
2. `JUDEX_THEME_DIR` set to a directory without `theme.toml`: `run`, `check` and `render-data` exit 2 with the path in the message; `--version` prints the upstream display plus a warning. Tests in Tasks 1 and 2.
3. `XDG_CONFIG_HOME` set to a relative path or empty string: the XDG spec says ignore it and use `~/.config`. Test in Task 3.
4. No home directory (`HOME` unset, as in distroless): lookup must not panic; it skips the XDG candidate and tries `/etc/<name>/config.yaml`. Test in Task 3.
5. `render-data` meta: `product_name` now carries the edition name; the appendix credit must still read `Generated by <theme product> <version>` once, not twice. Test in Task 2.

---

### Task 1: Theme resolution with an environment fallback (#12)

**Files:**
- Modify: `src/render/theme.rs`
- Modify: `src/pipeline.rs` (`load_inputs`, `check`, `Inputs`)
- Modify: `src/main.rs` (build the `Runtime`)
- Test: `src/render/theme.rs` unit tests, `tests/pipeline.rs`, `tests/cli.rs`

**Interfaces:**
- Produces in `render::theme`:
  ```rust
  /// Where the active theme came from, for `check` output and diagnostics.
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum ThemeSource { Config, Env, Default }
  impl std::fmt::Display for ThemeSource // "config" | "env" | "default"

  /// Configuration path first, then the environment directory, then the embedded default.
  pub fn resolve(config_dir: Option<&Path>, env_dir: Option<&Path>) -> Result<(Theme, ThemeSource), ThemeError>
  ```
  `load(dir: Option<&Path>)` stays as the single-directory loader that `resolve` calls.
- Produces in `pipeline`:
  ```rust
  /// What the binary knows and the library must not spell: upstream identity and environment.
  #[derive(Clone, Debug)]
  pub struct Runtime {
      /// Upstream product name, `PRODUCT_NAME` in `main.rs`.
      pub upstream: String,
      /// Crate version.
      pub version: String,
      /// Value of `<NAME>_THEME_DIR`, already read from the environment; `None` when unset.
      pub theme_dir: Option<PathBuf>,
      /// Name of that variable, for messages only.
      pub theme_dir_env: String,
  }
  ```
  `run`, `check`, `write_render_data` take `&Runtime` where they took `&ProductInfo`. `Inputs` gains `theme_source: ThemeSource`. (`ProductInfo` itself is reshaped in Task 2; in this task it is still built from `runtime.upstream`/`runtime.version`.)
- Consumes: `ThemeError` variants as they exist.

- [ ] **Step 1: Write the failing unit tests in `src/render/theme.rs`**

```rust
#[test]
fn resolve_prefers_config_over_env() {
    let (cfg_dir, env_dir) = (theme_dir_named("Config Edition"), theme_dir_named("Env Edition"));
    let (theme, source) = resolve(Some(cfg_dir.path()), Some(env_dir.path())).unwrap();
    assert_eq!((theme.product.name.as_str(), source), ("Config Edition", ThemeSource::Config));
}
#[test]
fn resolve_uses_env_when_config_is_absent() {
    let env_dir = theme_dir_named("Env Edition");
    let (theme, source) = resolve(None, Some(env_dir.path())).unwrap();
    assert_eq!((theme.product.name.as_str(), source), ("Env Edition", ThemeSource::Env));
}
#[test]
fn resolve_falls_back_to_default_when_neither_is_set() {
    let (theme, source) = resolve(None, None).unwrap();
    assert_eq!((theme, source), (default_theme(), ThemeSource::Default));
}
#[test]
fn resolve_rejects_an_env_dir_without_theme_toml() {
    let empty = tempfile::tempdir().unwrap();
    let err = resolve(None, Some(empty.path())).unwrap_err();
    assert!(matches!(err, ThemeError::Read(path, _) if path.ends_with("theme.toml")));
}
```
`theme_dir_named(name)` writes the embedded default `theme.toml` with `product.name` replaced into a `tempfile::TempDir` (the test helper lives in the test module).

- [ ] **Step 2: Run them and confirm they fail to compile**

Run: `cargo test --offline --lib theme::`
Expected: compile error, `resolve` and `ThemeSource` not found.

- [ ] **Step 3: Implement `ThemeSource` and `resolve` in `src/render/theme.rs`**

Doc comments on both, British spelling; `resolve` is four lines of precedence around `load`.

- [ ] **Step 4: Run the unit tests**

Run: `cargo test --offline --lib theme::`
Expected: PASS.

- [ ] **Step 5: Write the failing integration tests**

In `tests/pipeline.rs`, extend the `check` test so the expected string ends with `; product: judex 0.1.0; theme: default` (the exact version string comes from `env!("CARGO_PKG_VERSION")` in the test, not a literal), and add:

```rust
#[test]
fn check_reports_env_theme_and_config_precedence() {
    // env only → "theme: env" and the env theme's product name in the PDF credit
    // config + env → "theme: config"
}
```
In `tests/cli.rs` add `check_fails_with_exit_2_when_theme_dir_env_is_invalid`: run `judex check --config <trivy example>` with `JUDEX_THEME_DIR=<empty tempdir>`; expect exit 2 and stderr containing the directory path and `theme.toml`. (`JUDEX_THEME_DIR` is a literal in tests, which the guard does not scan.)

- [ ] **Step 6: Run them to verify they fail**

Run: `cargo test --offline --test pipeline --test cli`
Expected: FAIL — `check` output lacks `theme:` source; env variable has no effect.

- [ ] **Step 7: Implement `Runtime` and thread it through `pipeline` and `main.rs`**

- `main.rs`: `const PRODUCT_NAME`, derive `let theme_dir_env = format!("{}_THEME_DIR", PRODUCT_NAME.to_uppercase());`, read `std::env::var_os(&theme_dir_env).map(PathBuf::from)`, build `Runtime`.
- `pipeline::load_inputs(cfg, runtime, now)`: `let (theme, theme_source) = theme::resolve(cfg.theme.path.as_deref(), runtime.theme_dir.as_deref()).map_err(ConfigError::from)?;`. Keep the theme → sinks → source error order.
- `check`: format tail `; product: {} {}; theme: {}` using `runtime.upstream`, `runtime.version`, `theme_source` (Task 2 replaces the product part).
- Update `tests/pipeline.rs`' `product()` helper to build a `Runtime`.

- [ ] **Step 8: Run the full suite, fmt and clippy**

Run: `cargo fmt --check && cargo clippy --offline --all-targets -- -D warnings && cargo test --offline`
Expected: all PASS, including `naming_single_source`.

- [ ] **Step 9: Commit**

```bash
git add src/render/theme.rs src/pipeline.rs src/main.rs tests/pipeline.rs tests/cli.rs
git commit -m "Resolve the theme from the environment when the configuration names none"
```

---

### Task 2: Product identity from the theme (#13)

**Files:**
- Modify: `src/pipeline.rs` (`ProductInfo`, `render_options`, `check`, `build_source` signature)
- Modify: `src/source/http.rs` (remove `USER_AGENT`; `client_from_tls` takes `user_agent: &str`)
- Modify: `src/source/harbor/mod.rs`, `src/source/neuvector/mod.rs` or wherever `client_from_tls` is called; `src/sink/http.rs` if it builds a client
- Modify: `src/main.rs` (`version`, `--version`)
- Modify: `src/cli.rs` only if the `Version` subcommand needs a change (it should not)
- Test: `src/pipeline.rs` unit tests, `tests/http_client.rs`, `tests/harbor_source.rs`, `tests/cli.rs`, `tests/pipeline.rs`, `tests/render_summary.rs` (meta)

**Interfaces:**
- Produces in `pipeline`:
  ```rust
  pub struct ProductInfo {
      /// Name the report and the binary present: the theme's product name.
      pub name: String,
      /// Upstream product name, shown in parentheses when it differs from `name`.
      pub upstream: String,
      /// Crate version.
      pub version: String,
  }
  impl ProductInfo {
      pub fn new(runtime: &Runtime, theme: &Theme) -> Self;
      /// "judex 0.2.0" or "Arishem 0.2.0 (judex)".
      pub fn display(&self) -> String;
      /// "judex/0.2.0" or "Arishem/0.2.0 judex/0.2.0".
      pub fn user_agent(&self) -> String;
  }
  pub fn build_source(cfg: &SourceConfig, user_agent: &str) -> Result<Box<dyn ScanSource>, ConfigError>;
  ```
- Consumes: `Runtime`, `theme::resolve` from Task 1.

- [ ] **Step 1: Write the failing unit tests for `ProductInfo` in `src/pipeline.rs`**

```rust
#[test]
fn product_display_and_user_agent_for_default_theme() {
    let p = ProductInfo { name: "judex".into(), upstream: "judex".into(), version: "0.2.0".into() };
    assert_eq!(p.display(), "judex 0.2.0");
    assert_eq!(p.user_agent(), "judex/0.2.0");
}
#[test]
fn product_display_and_user_agent_for_edition_theme() {
    let p = ProductInfo { name: "Arishem".into(), upstream: "judex".into(), version: "0.2.0".into() };
    assert_eq!(p.display(), "Arishem 0.2.0 (judex)");
    assert_eq!(p.user_agent(), "Arishem/0.2.0 judex/0.2.0");
}
```
(The guard scans `src/`; use `"upstream"` as the upstream name in these tests instead of the literal product name — e.g. `name: "upstream"`, expected `"upstream 0.2.0"` — so the test module does not add a hit.)

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --offline --lib pipeline::`
Expected: compile error on the new fields/methods.

- [ ] **Step 3: Implement `ProductInfo::{new, display, user_agent}`**

`display`: `format!("{} {}", name, version)` plus ` ({upstream})` when `name != upstream`. `user_agent`: `format!("{}/{}", name, version)` plus ` {upstream}/{version}` when they differ. Product names in the UA must be a single token: replace whitespace in `name` with `-` (`Arishem Edition` → `Arishem-Edition`).

- [ ] **Step 4: Write the failing integration tests**

- `tests/http_client.rs`: the two places that build `image-scan-report/<ver>` become `upstream/<ver>` via an explicit `HttpOptions { user_agent, .. }`; add an assertion that `HttpOptions::default().user_agent` is empty — the default no longer carries a product string. Delete the `USER_AGENT` import.
- `tests/harbor_source.rs`: one request assertion that the mock saw `User-Agent: Edition/<ver> judex/<ver>` when the pipeline runs with a theme whose product name is `Edition` (`JUDEX_THEME_DIR` or `theme.path` in the test config).
- `tests/cli.rs`: `version_prints_product_name_and_semver` and `version_flag_prints_product_and_version` keep their default-theme expectations; add `version_uses_edition_name_from_theme_dir_env` (expect `Edition <ver> (judex)\n`) and `version_warns_but_prints_when_theme_dir_env_is_invalid` (stdout `judex <ver>\n`, stderr non-empty, exit 0).
- `tests/pipeline.rs`: `check` expectation becomes `; product: judex <ver>; theme: default`, and with an edition theme `; product: Edition <ver> (judex); theme: config`.
- `tests/cli.rs` `render-data`: `data["meta"]["product_name"]` is `"Edition"` when run with the edition theme; the appendix string `Generated by Edition <ver>` appears exactly once in the extracted appendix text (Review Focus 5).

- [ ] **Step 5: Run and confirm failure**

Run: `cargo test --offline --test http_client --test harbor_source --test cli --test pipeline`
Expected: FAIL on the new expectations.

- [ ] **Step 6: Implement**

- `http.rs`: delete `USER_AGENT`; `HttpOptions::default().user_agent` is `String::new()`; `client_from_tls(ca_file, insecure_skip_verify, timeout, user_agent: &str)`; `HttpClient::try_new` rejects an empty `user_agent` with `HttpError::Invalid`-style error (pick the existing variant used for bad options, or add one) so a forgotten caller fails loudly in tests.
- Sources and the HTTP sink receive the UA string from `build_source(cfg, user_agent)` / `build_sinks(cfg, user_agent)`.
- `pipeline::load_inputs`: resolve the theme first (Task 1), then `let product = ProductInfo::new(runtime, &theme);`, then sinks and source with `product.user_agent()`. Keep the theme → sinks → source error order. `Inputs` gains `product: ProductInfo`; `render_options` takes `&ProductInfo` and sets `product_name: product.name`.
- `check`: `…; product: {}; theme: {}` with `product.display()` and `theme_source`.
- `main.rs`: for `Version` and clap's `--version`, resolve `theme::resolve(None, runtime.theme_dir.as_deref())`; on `Err(e)` print `warning: {e}` to stderr and use the default theme; build `ProductInfo` and pass `display()` to `.version(...)` (enable clap's `string` feature in `Cargo.toml` for an owned string) and print it for the subcommand.

- [ ] **Step 7: Run the full suite, fmt and clippy**

Run: `cargo fmt --check && cargo clippy --offline --all-targets -- -D warnings && cargo test --offline`
Expected: all PASS. `grep -rn "image-scan-report/" src tests` returns nothing.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src tests
git commit -m "Take the product name from the theme for version, check and User-Agent"
```

---

### Task 3: Host configuration lookup (XDG) (#10, binary side)

**Files:**
- Modify: `src/cli.rs` (`config: Option<PathBuf>` on `Run`, `Check`, `RenderData`; help text "defaults to the standard locations, see README")
- Modify: `src/config.rs` (`pub fn default_path(...)`)
- Modify: `src/main.rs` (derive names, call the resolver)
- Test: `src/config.rs` unit tests, `tests/cli.rs`

**Interfaces:**
- Produces in `config`:
  ```rust
  /// Candidate configuration files in lookup order for a product called `name`:
  /// `$<NAME>_CONFIG`, `$XDG_CONFIG_HOME/<name>/config.yaml` (or `$HOME/.config/<name>/config.yaml`), `/etc/<name>/config.yaml`.
  /// `env` returns the value of a variable; it is a parameter so tests need not touch the process environment.
  pub fn candidate_paths(name: &str, env: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf>;
  /// First existing candidate, or `ConfigError::NotFound { candidates, moved_from: Option<PathBuf> }`.
  pub fn default_path(name: &str, env: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, ConfigError>;
  ```
  `ConfigError::NotFound` displays every candidate on its own line; when `/etc/report/config.yaml` exists it appends `configuration moved to /etc/<name>/config.yaml in 0.2.0`. Exit code 2 (it is a `ConfigError`).
- Consumes: nothing new.

- [ ] **Step 1: Write the failing unit tests in `src/config.rs`**

```rust
#[test]
fn candidates_follow_xdg_then_etc() {
    let env = |k: &str| match k { "XDG_CONFIG_HOME" => Some("/xdg".into()), "HOME" => Some("/home/u".into()), _ => None };
    assert_eq!(candidate_paths("prod", &env), [PathBuf::from("/xdg/prod/config.yaml"), "/etc/prod/config.yaml".into()]);
}
#[test]
fn explicit_env_variable_comes_first() { /* PROD_CONFIG=/x/c.yaml → first candidate */ }
#[test]
fn relative_or_empty_xdg_config_home_is_ignored() { /* XDG_CONFIG_HOME="rel" or "" → $HOME/.config/prod/config.yaml */ }
#[test]
fn missing_home_skips_the_xdg_candidate() { /* HOME unset, XDG unset → only /etc/prod/config.yaml */ }
#[test]
fn default_path_returns_first_existing() { /* tempdir as XDG_CONFIG_HOME with prod/config.yaml → that path */ }
#[test]
fn default_path_error_lists_candidates() { /* nothing exists → NotFound; Display contains every candidate */ }
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --offline --lib config::`
Expected: compile error.

- [ ] **Step 3: Implement `candidate_paths`, `default_path`, `ConfigError::NotFound`**

The `moved_from` check uses a plain `Path::new("/etc/report/config.yaml").is_file()` — the old path is a historical literal, not the product name, so the guard is unaffected.

- [ ] **Step 4: Run the unit tests**

Run: `cargo test --offline --lib config::`
Expected: PASS.

- [ ] **Step 5: Write the failing CLI tests in `tests/cli.rs`**

- Replace the test at line ~237 (`/etc/report/config.yaml` in stderr) with `missing_config_lists_candidates`: run `judex check` with `HOME` set to a tempdir and `XDG_CONFIG_HOME` unset; expect exit 2 and stderr containing `<tempdir>/.config/judex/config.yaml` and `/etc/judex/config.yaml`.
- `config_found_under_xdg_config_home`: copy the trivy example to `<tmp>/judex/config.yaml` (with paths rewritten absolute), set `XDG_CONFIG_HOME=<tmp>`, run `judex check` without `--config`; expect exit 0.
- `judex_config_env_overrides_lookup`: `JUDEX_CONFIG=<file>`; expect exit 0.

- [ ] **Step 6: Run and confirm failure**

Run: `cargo test --offline --test cli`
Expected: FAIL — `--config` still defaults to `/etc/report/config.yaml`.

- [ ] **Step 7: Implement in `cli.rs` and `main.rs`**

`config: Option<PathBuf>`; in `main.rs`, `let config = match config { Some(p) => p, None => config::default_path(PRODUCT_NAME, &|k| std::env::var_os(k))? };` once in `dispatch`.

- [ ] **Step 8: Run the full suite, fmt and clippy**

Run: `cargo fmt --check && cargo clippy --offline --all-targets -- -D warnings && cargo test --offline`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/cli.rs src/config.rs src/main.rs tests/cli.rs
git commit -m "Look up the configuration in XDG and /etc locations"
```

---

### Task 4: Image, deploy examples and CI on standard paths (#10, packaging side)

**Files:**
- Modify: `Containerfile` (`WORKDIR /var/lib/judex/reports`, `VOLUME ["/var/lib/judex/reports"]`, `CMD ["run"]`)
- Modify: `deploy/examples/config.yaml`, `config-neuvector.yaml`, `config-trivy-files.yaml` (`/etc/judex/ca.pem`, `/etc/judex/logo.png`, output `/var/lib/judex/reports`; the trivy example keeps `./tests/fixtures/trivy` + `./out` for host use, with a comment naming the container equivalents)
- Modify: `deploy/k8s/*.yaml` (mount paths; namespace and labels `judex`; names `judex` / `judex-once`), `deploy/k8s/README.md`
- Modify: `deploy/podman/run.sh` (mount targets; default `IMAGE` tag stays until release)
- Modify: `.github/workflows/ci.yml` smoke job (`/etc/judex/config.yaml`, `/var/lib/judex/{scans,reports}`; sed `path: /fixtures/trivy` → `path: /var/lib/judex/scans/trivy`; drop the explicit `--config` on the loop, keep one invocation with `--config` to prove the flag still works; add `docker run --rm -e JUDEX_THEME_DIR=/nonexistent judex:ci --version` expecting exit 0 and the warning)
- Test: `tests/deploy_manifests.rs` (mount paths, namespace, labels)

**Interfaces:** none new; values are the table in *Decisions*.

- [ ] **Step 1: Update `tests/deploy_manifests.rs` to the new paths and names and run it**

Run: `cargo test --offline --test deploy_manifests`
Expected: FAIL on every manifest.

- [ ] **Step 2: Edit the manifests, examples, wrapper, Containerfile and CI**

- [ ] **Step 3: Run the manifest test and build the image locally**

Run: `cargo test --offline --test deploy_manifests && podman build -t judex:dev -f Containerfile . && podman run --rm judex:dev --version`
Expected: PASS; `judex <ver>`.

- [ ] **Step 4: Smoke the image the way CI does**

Run the three `podman run` invocations from the CI job with `/etc/judex/config.yaml`, `/var/lib/judex/scans`, `/var/lib/judex/reports`, read-only root, UID 65532.
Expected: a PDF appears in the output directory; `check` prints `theme: default`.

- [ ] **Step 5: Commit**

```bash
git add Containerfile deploy .github/workflows/ci.yml tests/deploy_manifests.rs
git commit -m "Move image and deployment paths to FHS locations"
```

---

### Task 5: Documentation and changelog

**Files:**
- Modify: `README.md` (configuration reference: lookup order, `JUDEX_CONFIG`, `JUDEX_THEME_DIR`; container quick start paths; `check` sample output)
- Modify: `docs/container.md` (mount table, default command, environment table with `JUDEX_THEME_DIR`, "building an edition" section: `COPY theme/ /usr/share/<edition>/theme/` + `ENV JUDEX_THEME_DIR=/usr/share/<edition>/theme`)
- Modify: `deploy/k8s/README.md`, `docs/release.md` (rename procedure lists the derived environment variable names)
- Modify: `CHANGELOG.md` `[Unreleased]`: `### Changed` with the path table, namespace rename, `--version`/`check`/UA format; `### Added` with the lookup order and the theme variable; `### Removed` for `image-scan-report/` UA

- [ ] **Step 1: Write the documentation**

- [ ] **Step 2: Check every path and variable named in docs exists in code**

Run: `grep -rn '/etc/report\|/output\b\|image-scan-report' README.md docs/*.md deploy Containerfile .github` 
Expected: no hits except the historical note in `CHANGELOG.md` and `docs/superpowers/**`.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/container.md docs/release.md deploy/k8s/README.md CHANGELOG.md
git commit -m "Document standard paths, configuration lookup and edition theming"
```

---

## Self-review notes

- Spec coverage: #12 → Task 1; #13 → Task 2; #10 binary → Task 3, image/deploy → Task 4, docs → Task 5. The issue #10 text says `--config` is required; it has a default today (`/etc/report/config.yaml`), Task 3 replaces that default with the lookup.
- Naming guard: every `judex`-bearing name (`JUDEX_THEME_DIR`, `JUDEX_CONFIG`, `/etc/judex`, `judex/config.yaml`) is derived in `main.rs` or appears only in tests, docs, deploy and the Containerfile, which the guard does not scan.
- Type consistency: `Runtime` (Task 1) is what `ProductInfo::new` consumes (Task 2) and what `main.rs` builds once; `ThemeSource` is produced in Task 1 and printed in Tasks 1–2.
- Review Focus items 1–5 each have a named test above.

# judex

Container-image vulnerability scans (Harbor, NeuVector, Trivy) → bilingual audit PDF. Rust with Typst embedded. Read before changing anything:

- Design: `docs/superpowers/specs/2026-11-07-product-redesign-design.md`
- Decisions already taken and why: `docs/decisions.md` — read it before proposing a change of direction, and do not reopen what it closes
- Developer notes (tests, golden snapshots, previews, performance, fonts, strings): `docs/development.md`
- Release and rename procedure: `docs/release.md`
- Backlog: GitHub issues; the next version's scope is whatever is open there

## Rules

- Code, comments and docs in English with British spelling. Google's Rust Style Guide; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --offline` must pass before any commit.
- The product name is a literal only in `src/main.rs`; derived names and directories are computed there — see the [rename procedure](docs/release.md#rename-procedure).
- Where a published standard exists, follow it: FHS inside the image, XDG Base Directory on a host, OCI labels, RFC token rules for HTTP headers. Do not invent paths or conventions.
- Prefer the newest crates, base images and GitHub Actions; verify the latest version before pinning; Actions are SHA-pinned with a version comment.
- Secrets only from environment variables, never logged (including at trace level) and never in images or arguments.
- `docs/superpowers/plans/**` and `specs/**` are historical records: add new files, never edit old ones.
- Breaking changes are acceptable while 0.x, but every one goes in `CHANGELOG.md` under `[Unreleased]` with old → new.

## How work is done here

- Commits and PRs need the user's explicit word before push, merge, tag or publish. Tag and release deletion are the user's to run.
- Plans live in `docs/superpowers/plans/`; implementation is delegated task by task (Codex via the rescue subagent, briefs as files), the controller verifies fmt/clippy/tests and commits, a fresh reviewer checks each task, and the whole branch gets a final review before the PR.
- The Codex sandbox has no network, cannot bind loopback (mock-server tests fail there), cannot run podman and cannot write `.git`; plan briefs around that.
- See [local image builds](docs/container.md#local-build) for podman machine sizing.
- See [report design](docs/design/README.md) for PDF-page viewing tools.
- Fixture files under `tests/fixtures/` are captured data — never hand-edit or reduce them.

Personal and lab-environment details (test VM, accounts, this machine's tooling) are in `AGENTS.local.md`, git-ignored and not loaded automatically: read it when the lab or the local machine comes up.

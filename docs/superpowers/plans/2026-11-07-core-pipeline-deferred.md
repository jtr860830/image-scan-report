# Plan 1 — deferred items and rulings

Carried out of the execution ledger when plan 1 (core pipeline) finished on 2026-11-08. Each later plan's pre-flight should read this; items are fixed when a task touches the file, not before.

## Deferred minor findings

- T1: fixtures/neuvector-api/scanner.json keeps cluster-internal pod IP 10.42.0.35; README could label scanner:6 / podman / controller 5.6.4 as capture notes; note that ubuntu-18.04 has 0 findings in both tools and alpine-3.12 has 1; note the `library/` repository prefix in NeuVector scanner captures.
- T2: Cargo.toml lacks `description`; LICENSE appendix keeps the Apache placeholder; tests/cli.rs hard-codes "judex" (acceptable in a test).
- T3: snapshot does not pin secondary enum variants (En, NeuvectorFiles, NotScanned/Failed, ScannerLabel/Cvss2, WillNotFix/EndOfLife/FixDeferred/UnderInvestigation) nor Image/SourceInfo None fields; FixStatus::parse does not trim whitespace.
- T4: clean_score(Some(0.04)) returns Some(0.0) (filter before rounding) and +inf passes — filter after rounding and add is_finite(); duplicated select pattern in classify; case-sensitive source ordering; no doc comments on public items.
- T5: CVSS/References/RepoDigests use #[serde(default)] without Option so an explicit null rejects the file; fetch error-to-String conversion could be a helper; dedupe test hard to follow; redundant serde renames and a glob import; no doc comments on public items; file_modified_at only tested indirectly.
- T6: a vulnerability with severity: null fails the whole file (loud skip); file_name is deserialised but unused (plan-mandated).
- T6: NeuVector db_version/db_updated_at taken from the first file in path order, not the newest scan.
- T7: env-var tests race across threads (unique names mitigate); no `$${X}` escape for literal placeholders (document); resolve_env could use an is_env_name helper; Invalid messages do not name the offending output; no load()-level test for an unset header variable.
- T7: unknown-key tests assert only ConfigError::Parse, not the key name; UPLOAD_TOKEN restore is not a Drop guard.
- T8: tests use then_some("") as fixed_version; medium/low tie-break positions of rank() untested; stray blank line in lib.rs module list.
- T9: filesystem sink temp file name is fixed (.<name>.tmp) so two concurrent writers to the same file could collide.
- T9: no sync_all before rename (durability); temp file mode is default 0666-umask — consider 0o600 for report files.
- T10: README quick-start prose embeds counts that will go stale; rename note wording; some repeated content.
- parked: single-parse turns some unrelated/malformed JSON from "not recognised" skips into "invalid" skips (still skipped during fetch) — Ruling: acceptable; fetch behaviour is unchanged and the warning is louder, not quieter. Cost if wrong: a direct caller of parse_* sees Err instead of Ok(None).
- parked: a non-NeuVector JSON object carrying a non-empty error_message becomes a failed image named after its parent directory; with `path: .` the reference could be empty — Ruling: acceptable for this milestone; plan 3 may add a stricter envelope check. Cost if wrong: a spurious failed row in the appendix.
- parked: README line 30 wording about `check`; JUDEX_* env-var names in tests; read-only env tests do not take ENV_LOCK; a PDF-only config passes `check` but exits 4 under `run` — Ruling: all deferred to plan 2 (which replaces the PDF branch) or cosmetic.

## Notes for later plans

- plan 3: Finding.image is the reference string, so two images with the same reference but different digests (multi-arch children) would share one key. Plan 3's Harbor source must make child references unique (e.g. append the platform, or key findings by digest) — ruling deferred to plan 3's pre-flight.
- plan 2: `deny_unknown_fields` means the `theme` configuration key must be added when theming lands; a PDF-only configuration passes `check` but exits 4 under `run` until the renderer exists.
- plan 3: capture a real failed NeuVector scan (non-existent tag) in the lab; the failure envelope fixture is synthetic.

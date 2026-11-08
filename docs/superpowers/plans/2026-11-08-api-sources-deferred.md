# Plan 3 — deferred items and rulings

Carried out of the execution ledger when plan 3 (API sources) finished on 2026-11-08. Plan 4 pre-flight should read this; items are fixed when a task touches the file, not before.

## Plan 4 follow-ups

- ~~Render Image.tags in image detail (spec 6.1: "all its tags").~~ done (plan 4, Task 3)
- NeuVector rows have no platform or fix_status; account for these gaps in rendering.
- Harbor os is only the manifest OS, typically "linux", rather than a distro.
- check downloads every vulnerability report (65 s on the lab); consider a scope-only mode.
- ~~check should surface scan-state counts: a registry whose images are all scanning currently prints "0 findings".~~ done (plan 4, Task 3)
- Fetch Harbor reports concurrently.
- ~~Add judex --version.~~ done (plan 4, Task 3)
- Consider module layout neuvector/{controller,file,api,report}.rs.
- Unify test-support module inclusion.
- Populate Harbor db_version from scanner metadata.

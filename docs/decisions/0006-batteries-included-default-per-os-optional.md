# 6. All five OS readers on by default; per-OS features only for lean third-party reuse

Date: 2026-07-24
Status: Accepted

## Context

Two fleet rules meet here. "Batteries-Included — Compile Everything In" says a
forensic tool must do the whole job from one artifact and that
`default-features = false` must never be used to slim a fleet dependency — but it
carves out the library case: a library's `default` may stay lean *for
third-party reuse* so long as every fleet binary that links it turns the full set
on. ADR 0002 gives each platform its own optional-dependency tail (`sqlite-core`
for iOS, `percent-encoding` for Linux), so a naive "all optional, none default"
split would leave the zero-config path unable to read four of five platforms.

## Decision

Default to **all five** platforms in both crates: `default = ["windows", "linux",
"macos", "android", "ios"]` (`trash-core/Cargo.toml`, `trash-forensic/Cargo.toml`).
The zero-config `trash-forensic = "…"` dependency, and every fleet binary that
links it (e.g. `issen`), is fully capable across every OS with no feature
knowledge required.

The per-OS features exist for the *outside* single-platform consumer only: a tool
that needs just the Windows Recycle Bin reader builds `--no-default-features
--features windows` and drops the iOS SQLite engine and the Linux percent-decoder.
Slimming is the outside consumer's opt-in, never the fleet path — matching the
batteries-included library exception exactly.

## Consequences

- The default path is capable-by-default: point it at any platform's trash and it
  reads, with no `--features` incantation.
- A single-platform third-party consumer can shrink the dependency tree
  deliberately.
- The MSVR/dependency floor of the full default is what fleet binaries carry;
  keeping the default full means the common path is never silently missing a
  platform (the failure batteries-included exists to prevent).

# 8. MSRV declared at the pinned toolchain (1.96), not a low library floor

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy distinguishes apps from published libraries: apps declare
`rust-version` = the pinned dev toolchain, while **published libraries keep a
low, CI-verified MSRV** (e.g. `1.75`/`1.80`) as a deliberate compatibility
feature — `browser-forensic`, for instance, holds `1.80` workspace-wide. Both
crates here are published libraries, so the norm would be a low floor.

Instead, `[workspace.package]` declares `rust-version = "1.96"` (`Cargo.toml`),
inherited by both members via `rust-version.workspace = true`, which equals the
pinned dev toolchain (`rust-toolchain.toml` `channel = "1.96.0"`) — the *app*
pattern, applied to libraries.

## Decision

Keep the declared MSRV at `1.96`, matching the pinned toolchain, rather than
lowering and CI-verifying a separate low floor. This is the current, honest
state of the manifests; it makes the declared MSRV exactly what CI builds and
tests.

## Consequences

- The declared MSRV matches the toolchain the crates are actually built against —
  no separate low-MSRV CI job to keep honest.
- The trade-off is a narrower crates.io audience than a low-floor library would
  reach: a consumer on an older stable cannot build these crates. If broad
  reuse becomes a goal, lowering the floor and adding a verified low-MSRV job is
  the follow-up (raising MSRV later is near-breaking; lowering it is safe).

## Note on rationale

Rationale reconstructed from structure; original intent not recovered in
available history. The git log records no decision to hold the MSRV at the pinned
toolchain rather than lower it, and it is not established whether a transitive
dependency (`forensicnomicon`, `sqlite-core`) forces `1.96` or whether the low
floor was simply never set. This ADR records the observed state, not an inferred
motive.

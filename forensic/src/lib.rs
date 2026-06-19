//! Forensic anomaly analysis for Windows Recycle Bin `$I`/`$R` artifacts.
//!
//! Stub: public API only — implementation lands in the GREEN commit.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::Finding;
use recyclebin_core::{RecycleBinIndex, RecycleBinPair};

/// Audit a parsed `$I` record together with its `$I`/`$R` pairing, returning
/// canonical findings for any anomaly. (Stub: no findings yet.)
#[must_use]
pub fn audit_pair(_index: &RecycleBinIndex, _pair: &RecycleBinPair) -> Vec<Finding> {
    Vec::new()
}

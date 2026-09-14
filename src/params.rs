//! Benchmark parameters — single source of truth for both bench binaries.
//!
//! Edit here; both `benches/server.rs` (Criterion) and `src/bench_*.rs`
//! (mobile runner) pick up the change automatically.

/// Batch sizes for the Add phase (new members per epoch).
pub const ADD_BATCH: &[usize] = &[1, 1 << 10, 1 << 12, 1 << 14, 1 << 16];

/// Batch sizes for Revocation and Holder Update (deletions / epoch).
pub const DEL_BATCH: &[usize] = &[1, 1 << 3, 1 << 6, 1 << 9, 1 << 12];

/// Number of attributes in the server-signed gap attestation (BBS-2023 / ECDSA).
///
/// Attributes: lower_id, upper_id, expiry_ts.
/// Used in `benches/server.rs` for the server-side signing benchmark.
pub const BBS_ATTR_COUNT: u32 = 3;

/// Number of attributes in the holder's BBS-2023 revocation credential.
///
/// Adds `rev_handle` (the holder's integer identifier) to the three gap
/// attributes above, so the mobile range proof can bind the holder's position
/// within a gap without revealing it.
pub const BBS_CRED_ATTR_COUNT: u32 = 4;

/// Dummy expiry timestamp used in gap signatures during benchmarks.
pub const EXPIRY_TS: u64 = 1_900_000_000;

/// Base number of gaps already present in the signed-pair list *before*
/// the current epoch's k revocations are applied.
///
/// For list-based schemes (BBS+BPP, ECDSA) the issuer must **re-sign the
/// entire list** each epoch because every gap signature binds the current
/// epoch number.  If the list already has `LIST_BASE_SIZE` gaps and k new
/// revocations are processed this epoch, the issuer re-signs
/// `LIST_BASE_SIZE + k + 1` gaps (each revocation splits one gap → +1 gap
/// per revocation; the +1 for the initial split).
///
/// Contrast with accumulator schemes (KB21, CL-RSA-B) where the issuer
/// only publishes a batch-delete message proportional to k, regardless of
/// total members.
///
/// Tune this to the expected steady-state revocation list length.
///
/// 100,000 is a deliberately conservative fraction of the CIE's real,
/// currently-revoked count (~440,000; see the paper's experimental setup):
/// both re-signing cost and list payload size are just this constant times a
/// fixed per-gap rate, so results at the CIE's real scale can be obtained by
/// linear extrapolation rather than re-benchmarking at a larger N.
pub const LIST_BASE_SIZE: usize = 100_000;

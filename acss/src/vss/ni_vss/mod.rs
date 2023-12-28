//! Non-interactive Verifiable Secret Sharing using Groth20 with BLS12-381.
mod chunking;
pub(crate) mod dealing;
pub(crate) mod dlog_recovery;
pub(crate) mod encryption;
mod fiat_shamir;
pub(crate) mod nizk_chunking;
pub(crate) mod nizk_sharing;
mod utils;
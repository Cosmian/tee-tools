use std::path::PathBuf;

pub mod error;
pub mod key;
pub mod mrsigner;
pub mod policy;
pub mod quote;
pub mod verify;

pub const REPORT_DATA_SIZE: usize = 64;
pub const MRENCLAVE_SIZE: usize = 32;
pub const MRSIGNER_SIZE: usize = 32;

pub(crate) const SGX_GUEST_PATH: &str = "/dev/attestation/quote";

/// Test whether the current environment is under SGX
#[must_use]
pub fn is_sgx() -> bool {
    PathBuf::from(SGX_GUEST_PATH).exists()
}

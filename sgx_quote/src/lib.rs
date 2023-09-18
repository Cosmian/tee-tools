use std::path::PathBuf;

pub mod error;
pub mod key;
pub mod mrsigner;
pub mod quote;
mod verify;

pub fn is_sgx() -> bool {
    PathBuf::from("/dev/attestation/quote").exists()
}

use std::path::PathBuf;

pub mod error;
pub mod mrsigner;
pub mod quote;
pub mod verify;

pub fn is_sgx() -> bool {
    let path = PathBuf::from("/dev/attestation/quote");
    path.exists()
}

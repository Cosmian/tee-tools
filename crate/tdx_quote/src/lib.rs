use std::path::PathBuf;

pub mod error;
pub mod policy;
pub mod quote;
mod verify;

pub const REPORT_DATA_SIZE: usize = 64;
pub(crate) const TDX_GUEST_PATH: &str = "/dev/tdx_guest";

/// Test whether the current environment is under TDX
pub fn is_tdx() -> bool {
    PathBuf::from(TDX_GUEST_PATH).exists()
}

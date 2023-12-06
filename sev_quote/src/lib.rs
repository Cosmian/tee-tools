use std::path::PathBuf;

pub mod error;
#[cfg(target_os = "linux")]
pub mod key;
pub mod policy;
pub mod quote;
pub mod snp_extension;
pub mod verify;

pub const REPORT_DATA_SIZE: usize = 64;

pub fn is_sev() -> bool {
    PathBuf::from("/dev/sev-guest").exists()
}

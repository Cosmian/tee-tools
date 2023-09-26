use std::path::PathBuf;

pub mod error;
#[cfg(target_os = "linux")]
pub mod key;
pub mod quote;
pub mod snp_extension;

pub fn is_sev() -> bool {
    PathBuf::from("/dev/sev-guest").exists()
}

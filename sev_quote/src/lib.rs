use std::path::PathBuf;

pub mod error;
pub mod quote;
pub mod snp_extension;

pub fn is_sev() -> bool {
    let path = PathBuf::from("/dev/sev-guest");
    path.exists()
}

pub mod error;
#[cfg(target_os = "linux")]
mod generate;
pub mod quote;

pub const REPORT_DATA_SIZE: usize = 64;

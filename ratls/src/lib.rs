use crate::error::Error;

pub mod error;
pub mod extension;
#[cfg(target_os = "linux")]
pub mod generate;
pub mod verify;

pub enum TeeType {
    Sgx,
    Sev,
}

pub enum TeeMeasurement {
    Sgx {
        mr_signer: [u8; 32],
        mr_enclave: [u8; 32],
    },
    Sev([u8; 48]),
}

/// Tell whether the platform is an SGX or an SEV processor
pub fn guess_tee() -> Result<TeeType, Error> {
    if sev_quote::is_sev() {
        return Ok(TeeType::Sev);
    }

    if sgx_quote::is_sgx() {
        return Ok(TeeType::Sgx);
    }

    Err(Error::UnsupportedTeeError)
}

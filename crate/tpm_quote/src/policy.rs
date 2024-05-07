use serde::{Deserialize, Serialize};
use tss_esapi::{structures::Attest, traits::UnMarshall};

use crate::error::Error;

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the tpm quote values
pub struct TpmPolicy {
    // The number of occurrences of TPM Reset since the last TPM2_Clear
    pub reset_count: Option<u32>,
    // The number of times that TPM2_Shutdown or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear
    pub restart_count: Option<u32>,
}

impl TryFrom<&[u8]> for TpmPolicy {
    type Error = Error;
    fn try_from(attest: &[u8]) -> Result<Self, Error> {
        let attest = Attest::unmarshall(attest)?;

        Ok(TpmPolicy {
            reset_count: Some(attest.clock_info().reset_count()),
            restart_count: Some(attest.clock_info().restart_count()),
        })
    }
}

impl TpmPolicy {
    #[must_use]
    pub fn new() -> Self {
        TpmPolicy {
            ..Default::default()
        }
    }
}

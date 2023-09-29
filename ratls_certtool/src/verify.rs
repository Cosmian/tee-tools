use anyhow::Result;
use clap::Args;
use hex::decode;
use ratls::verify::verify_ratls;
use std::fs;
use std::path::PathBuf;
use tee_attestation::{SevMeasurement, SgxMeasurement, TeeMeasurement};

/// Verify a RATLS certificate
#[derive(Args, Debug)]
#[clap(verbatim_doc_comment)]
pub struct VerifyArgs {
    /// Path of the certificate to verify
    #[arg(short, long)]
    cert: PathBuf,

    /// Expected value of the SEV measurement
    #[arg(long, required = false)]
    measurement: Option<String>,

    /// Expected value of the SGX mrenclave
    #[arg(long, required = false)]
    mrenclave: Option<String>,

    /// Path of the SGX enclave signer key (to compute the SGX mrsigner)
    #[arg(long)]
    public_signer_key: Option<PathBuf>,
}

impl VerifyArgs {
    pub fn run(&self) -> Result<()> {
        let public_signer_key = if let Some(path) = &self.public_signer_key {
            Some(fs::read_to_string(path)?)
        } else {
            None
        };

        let mrenclave = if let Some(v) = &self.mrenclave {
            Some(decode(v)?.as_slice().try_into()?)
        } else {
            None
        };

        let sev_measurement = if let Some(v) = &self.measurement {
            Some(decode(v)?.as_slice().try_into()?)
        } else {
            None
        };

        let measurement = match (public_signer_key, mrenclave, sev_measurement) {
            (None, None, None) => TeeMeasurement {
                sgx: None,
                sev: None
            },
            (Some(s), Some(e), None) => TeeMeasurement {
                sgx: Some(SgxMeasurement {
                    public_signer_key_pem: s.to_string(), mr_enclave: e
                }),
                sev: None
            },
            (None, None, Some(m)) => TeeMeasurement {
                sgx: None,
                sev: Some(SevMeasurement(m))
            },
            _ => anyhow::bail!("Bad measurements combination. It should be [None | (--mrenclave & --signer_key) | measurement]")
        };

        verify_ratls(fs::read_to_string(&self.cert)?.as_bytes(), measurement)?;

        println!("Verification succeed!");

        Ok(())
    }
}

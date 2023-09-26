use anyhow::Result;
use clap::Args;
use hex::decode;
use ratls::{verify::verify_ratls, TeeMeasurement};
use sgx_quote::mrsigner::compute_mr_signer;
use std::fs;
use std::path::PathBuf;

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
    signer_key: Option<PathBuf>,
}

impl VerifyArgs {
    pub fn run(&self) -> Result<()> {
        let mr_signer = if let Some(path) = &self.signer_key {
            Some(
                compute_mr_signer(&fs::read_to_string(path)?)?
                    .as_slice()
                    .try_into()?,
            )
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

        let measurement = match (mr_signer, mrenclave, sev_measurement) {
            (None, None, None) => None,
            (Some(s), Some(e), None) => Some(TeeMeasurement::Sgx { mr_signer: s, mr_enclave: e }),
            (None, None, Some(m)) => Some(TeeMeasurement::Sev (m)),
            _ => anyhow::bail!("Bad measurements combination. It should be [None | (--mrenclave & --signer_key) | measurement]")
        };

        verify_ratls(fs::read_to_string(&self.cert)?.as_bytes(), measurement)?;

        println!("Verification succeed!");

        Ok(())
    }
}

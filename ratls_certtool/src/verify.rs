use anyhow::Result;
use clap::Args;
use hex::decode;
use ratls::verify_ratls;
use sgx_quote::mrsigner::compute_mr_signer;
use std::fs;
use std::path::PathBuf;

/// Generate a RATLS certificate
#[derive(Args, Debug)]
#[clap(verbatim_doc_comment)]
pub struct VerifyArgs {
    /// Path of the generated certificate
    #[arg(short, long)]
    cert: PathBuf,

    /// Expected value of the mrenclave
    #[arg(short, long, required = false)]
    mrenclave: Option<String>,

    /// Path of the enclave signer key
    #[arg(short, long)]
    signer_key: PathBuf,
}

impl VerifyArgs {
    pub fn run(&self) -> Result<()> {
        let mr_signer = compute_mr_signer(&fs::read_to_string(self.signer_key.clone())?)?;

        let mrenclave = if let Some(v) = self.mrenclave.clone() {
            Some(decode(v)?.as_slice().try_into()?)
        } else {
            None
        };

        verify_ratls(
            fs::read_to_string(&self.cert)?.as_bytes(),
            mrenclave,
            Some(mr_signer),
        )?;

        Ok(())
    }
}

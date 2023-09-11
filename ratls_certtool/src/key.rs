use anyhow::Result;
use clap::Args;
use openssl::pkey::{Id, PKey};
use ratls::{guess_tee, TeeType};
use std::fs;
use std::path::PathBuf;

/// Generate a X25519 key derived from the measurements
#[derive(Args, Debug)]
pub struct KeyArgs {
    /// Path of the generated key
    #[arg(short, long, default_value = PathBuf::from(".").into_os_string())]
    output: PathBuf,

    /// If set, no salt is used when deriving the key
    #[arg(long, action)]
    no_salt: bool,
}

impl KeyArgs {
    pub fn run(&self) -> Result<()> {
        let public_key_path = self.output.join(PathBuf::from("key.pub"));
        let private_key_path = self.output.join(PathBuf::from("key.pem"));

        let secret = match guess_tee()? {
            TeeType::Sgx => sgx_quote::key::get_key(!self.no_salt)?,
            TeeType::Sev => sev_quote::key::get_key(!self.no_salt)?,
        };
        let public_key = PKey::private_key_from_raw_bytes(&secret, Id::X25519)?.raw_public_key()?;

        fs::create_dir_all(&self.output)?;
        fs::write(&private_key_path, secret)?;
        fs::write(&public_key_path, public_key)?;

        println!("Private key: {private_key_path:?}");
        println!("Public key: {public_key_path:?}");

        Ok(())
    }
}

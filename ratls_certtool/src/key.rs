use anyhow::{anyhow, Result};
use clap::Args;
use curve25519_dalek::{constants::X25519_BASEPOINT, scalar::Scalar};
use ratls::{guess_tee, TeeType};
use std::convert::TryInto;
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
        let public_key_path = self.output.join(PathBuf::from("x25519_sk.bin"));
        let private_key_path = self.output.join(PathBuf::from("x25519_pk.bin"));

        let secret = match guess_tee()? {
            TeeType::Sgx => sgx_quote::key::get_key(!self.no_salt)?,
            TeeType::Sev => sev_quote::key::get_key(!self.no_salt)?,
        };
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| anyhow!("unexpected X25519 secret key"))?;
        let sk =
            Scalar::from_canonical_bytes(secret).ok_or(anyhow!("unexpected X25519 secret key"))?;
        let pk = sk * X25519_BASEPOINT;

        fs::create_dir_all(&self.output)?;
        fs::write(&private_key_path, secret)?;
        fs::write(&public_key_path, pk.to_bytes())?;

        println!("Private key: {private_key_path:?}");
        println!("Public key: {public_key_path:?}");

        Ok(())
    }
}

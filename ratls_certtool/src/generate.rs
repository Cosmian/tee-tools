use anyhow::{anyhow, Result};
use clap::Args;
use ratls::generate_ratls_cert;
use std::fs;
use std::path::PathBuf;

/// Generate a RATLS certificate
#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Subject as an RFC 4514 string for the RA-TLS certificate
    #[arg(
        short,
        long,
        default_value_t = String::from("CN=cosmian.io,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France")
    )]
    subject: String,

    /// Subject Alternative Name in the RA-TLS certificate
    #[arg(long, default_value_t = String::from("localhost"))]
    san: String,

    /// Number of days before the certificate expires
    #[arg(short, long, default_value_t = 365)]
    days: u64,

    /// A file containing 32 bytes to add into the quote report data section
    #[arg(short, long)]
    extra_data: Option<PathBuf>,

    /// Path of the generated certificate
    #[arg(short, long, default_value = PathBuf::from(".").into_os_string())]
    output: PathBuf,
}

impl GenerateArgs {
    pub fn run(&self) -> Result<()> {
        let extra_data: Option<[u8; 32]> = if let Some(extra_data_file) = &self.extra_data {
            let extra_data = fs::read(extra_data_file)?;
            if extra_data.len() > 32 {
                return Err(anyhow!(
                    "Your extra data file should contain at most 32 bytes (read: {}B)",
                    extra_data.len()
                ));
            }
            let extra_data_padding = vec![0; 32 - extra_data.len()];
            let extra_data = [extra_data, extra_data_padding].concat();
            Some(extra_data[0..32].try_into()?)
        } else {
            None
        };

        let (private_key, cert) = generate_ratls_cert(
            &self.subject,
            &self.subject,
            vec![&self.san],
            self.days,
            extra_data,
        )?;

        let key_path = self.output.join(PathBuf::from("key.ratls.pem"));
        let cert_path = self.output.join(PathBuf::from("cert.ratls.pem"));

        fs::create_dir_all(&self.output)?;
        fs::write(&key_path, private_key)?;
        fs::write(&cert_path, cert)?;

        println!("RATLS private key: {key_path:?}");
        println!("RATLS certificate: {cert_path:?}");

        Ok(())
    }
}

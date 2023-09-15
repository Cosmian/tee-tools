use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::Args;
use ratls::get_server_certificate;

/// Fetch an RATLS certificate from a domain name
#[derive(Args, Debug)]
pub struct FetchArgs {
    /// The server name to fetch
    #[arg(long, action)]
    hostname: String,

    /// The port to fetch
    #[arg(long, short, action)]
    port: u32,

    /// Path of the fetched certificate
    #[arg(short, long, default_value = PathBuf::from(".").into_os_string())]
    output: PathBuf,
}

impl FetchArgs {
    pub fn run(&self) -> Result<()> {
        let cert = get_server_certificate(&self.hostname, self.port)?;

        let cert_path = self.output.join(PathBuf::from("cert.ratls.pem"));

        fs::create_dir_all(&self.output)?;
        fs::write(&cert_path, cert)?;

        println!("RATLS certificate: {cert_path:?}");

        Ok(())
    }
}

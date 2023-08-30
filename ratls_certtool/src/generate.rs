use anyhow::{anyhow, Result};
use clap::Args;
use ratls::generate_ratls_cert;
use std::collections::HashMap;
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
    days: u32,

    /// A file containing 32 bytes to add into the quote report data section
    #[arg(short, long)]
    extra_data: Option<PathBuf>,

    /// Path of the generated certificate
    #[arg(short, long, default_value = PathBuf::from(".").into_os_string())]
    output: PathBuf,
}

/// Parse a rfc4514 string.
///
/// Example: CN=cosmian.io,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France"
fn parse_rfc4514_string(s: &str) -> Result<HashMap<String, String>> {
    let fields = s.split(',');
    let mut key_values = HashMap::new();
    for field in fields.into_iter() {
        let key_value: Vec<&str> = field.split('=').collect();
        if key_value.len() != 2 {
            return Err(anyhow!("'{s}' is malformed!"));
        }
        if key_value[0].is_empty() || key_value[1].is_empty() {
            return Err(anyhow!("'{s}' is malformed!"));
        }

        key_values.insert(
            key_value[0].trim().to_owned(),
            key_value[1].trim().to_owned(),
        );
    }
    Ok(key_values)
}

impl GenerateArgs {
    pub async fn run(&self) -> Result<()> {
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

        // TODO: Demo code, remove that
        // BEGIN
        let unique_data: [u8; 64] = [
            65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97, 119,
            101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104, 101, 32,
            98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111, 99, 107, 115,
            33, 33, 33, 33, 33, 33,
        ];
        let (attestation, certs) = sev_quote::quote::get_quote(&unique_data)?;
        println!("{attestation:?}");
        sev_quote::quote::verify_quote(&attestation, &certs)
            .await
            .unwrap();
        println!("{attestation:?}");
        // END

        let subject = parse_rfc4514_string(&self.subject)?;

        let (private_key, cert_key) = generate_ratls_cert(
            subject.get("C").map(|x| x.as_str()),
            subject.get("ST").map(|x| x.as_str()),
            subject.get("L").map(|x| x.as_str()),
            subject.get("O").map(|x| x.as_str()),
            subject.get("CN").map(|x| x.as_str()),
            vec![&self.san],
            self.days,
            extra_data,
        )?;

        let key_path = self.output.join(PathBuf::from("key.ratls.pem"));
        let cert_path = self.output.join(PathBuf::from("cert.ratls.pem"));

        fs::create_dir_all(&self.output)?;
        fs::write(&key_path, private_key.private_key_to_pem_pkcs8()?)?;
        fs::write(&cert_path, cert_key.to_pem()?)?;

        println!("RATLS private key: {key_path:?}");
        println!("RATLS certificate: {cert_path:?}");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc4514_string() {
        assert!(parse_rfc4514_string("CN=cosmian.io").is_ok()); // One key_value
        assert!(parse_rfc4514_string("CN=cosmian.io,T=3").is_ok()); // More than one key_values
        assert!(parse_rfc4514_string("CN=cosmian.io,CN=cosmian.io").is_ok()); // Twice the same key_value
        assert!(parse_rfc4514_string("test").is_err()); // Not a key_value
        assert!(parse_rfc4514_string("").is_err()); // Empty string
        assert!(parse_rfc4514_string("CN=cosmian.io=3").is_err()); // Missing comma and key
        assert!(parse_rfc4514_string("CN=cosmian.io,=3").is_err()); // Missing key
        assert!(parse_rfc4514_string("CN=cosmian.io,A=").is_err()); // Missing value

        // Check the parsing
        let subject =
            parse_rfc4514_string("CN=cosmian.io,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France")
                .unwrap();
        assert_eq!(subject["CN"], String::from("cosmian.io"));
        assert_eq!(subject["O"], String::from("Cosmian Tech"));
        assert_eq!(subject["C"], String::from("FR"));
        assert_eq!(subject["L"], String::from("Paris"));
        assert_eq!(subject["ST"], String::from("Ile-de-France"));

        // Check the trim
        let subject = parse_rfc4514_string(" CN = cosmian.io , O = Cosmian Tech ").unwrap();
        assert_eq!(subject["CN"], String::from("cosmian.io"));
        assert_eq!(subject["O"], String::from("Cosmian Tech"));
    }
}

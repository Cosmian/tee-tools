use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TCP connection failed")]
    ConnectionError,
    #[error("HostParseError: `{0}`")]
    HostParseError(String),
    #[error(transparent)]
    InvalidDnsNameError(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("No Certificate Error")]
    NoCertificateError,
    #[error(transparent)]
    RustTLSError(#[from] rustls::Error),
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
}

#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
            .to_vec()
    }
}

/// A TLS verifier adding the ability to match the leaf certificate with a trusted one.
#[derive(Debug)]
pub struct LeafCertificateVerifier {
    // The certificate we expect to see in the TLS connection
    expected_cert: CertificateDer<'static>,
    // A default verifier to run anyway
    default_verifier: Arc<dyn ServerCertVerifier>,
}

impl LeafCertificateVerifier {
    pub fn new(
        expected_cert: &CertificateDer<'static>,
        default_verifier: Arc<dyn ServerCertVerifier>,
    ) -> Self {
        Self {
            expected_cert: expected_cert.clone(),
            default_verifier,
        }
    }
}

impl ServerCertVerifier for LeafCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Verify the leaf certificate
        if !end_entity.eq(&self.expected_cert) {
            return Err(rustls::Error::General(
                "Leaf certificate doesn't match the expected one".to_owned(),
            ));
        }

        // Now proceed with typical verifications
        self.default_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
            .to_vec()
    }
}

pub fn get_tls_certificates(host: &str, port: u16) -> Result<Vec<Vec<u8>>, Error> {
    // Build TLS config with NO verification
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
            .with_no_client_auth(),
    );

    // Server name (must match SNI format, even if not verified)
    let server_name = ServerName::try_from(host.to_string())?;

    // Create TLS connection
    let mut conn = rustls::ClientConnection::new(config, server_name)?;

    // TCP connection
    let mut sock = std::net::TcpStream::connect(format!("{host}:{port}"))?;

    // Complete TLS handshake
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }

    // Extract peer certificates
    if let Some(certs) = conn.peer_certificates() {
        return Ok(certs
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>());
    }

    Err(Error::NoCertificateError)
}

pub fn get_tls_certificate(host: &str, port: u16) -> Result<Vec<u8>, Error> {
    return Ok(get_tls_certificates(host, port)?
        .first()
        .ok_or(Error::NoCertificateError)?
        .to_owned());
}

pub fn get_tls_certificates_from_url(url: &str) -> Result<Vec<Vec<u8>>, Error> {
    let agent_url_parsed: url::Url = url::Url::parse(url)?;
    let host = agent_url_parsed
        .host_str()
        .ok_or_else(|| Error::HostParseError(format!("Host not found in url: {url}")))?;
    let port = agent_url_parsed.port().unwrap_or(443);

    get_tls_certificates(host, port)
}

pub fn get_tls_certificate_from_url(url: &str) -> Result<Vec<u8>, Error> {
    return Ok(get_tls_certificates_from_url(url)?
        .first()
        .ok_or(Error::NoCertificateError)?
        .to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, pem::PemObject};

    #[test]
    fn test_google_certificate() {
        // To fetch Google's certificate:
        // openssl s_client -showcerts -connect google.com:443 </dev/null 2>/dev/null | openssl x509 -outform PEM>data/google.pem
        let expected_server_cert =
            CertificateDer::from_pem_slice(include_bytes!("../data/google.pem"))
                .unwrap()
                .to_vec();
        let server_cert = get_tls_certificate("google.com", 443).unwrap();

        assert_eq!(expected_server_cert, server_cert);
    }

    #[test]
    fn test_letsencrypt_certificate() {
        // To fetch Let's Encrypt's certificate:
        // openssl s_client -showcerts -connect letsencrypt.org:443 </dev/null 2>/dev/null | openssl x509 -outform PEM>data/letsencrypt.pem
        let expected_server_cert =
            CertificateDer::from_pem_slice(include_bytes!("../data/letsencrypt.pem"))
                .unwrap()
                .to_vec();
        let server_cert = get_tls_certificate("letsencrypt.org", 443).unwrap();

        assert_eq!(expected_server_cert, server_cert);
    }
}

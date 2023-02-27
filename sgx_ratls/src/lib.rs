use crate::error::RATLSError;
use rustls::{
    client::ServerCertVerified,
    client::{ServerCertVerifier, ServerName},
    Certificate, Error,
};
use std::io::Write;
use std::time::SystemTime;

pub mod error;

pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,                    // end_entity
        _: &[Certificate],                  // intermediates
        _: &ServerName,                     // server_name
        _: &mut dyn Iterator<Item = &[u8]>, // scts
        _: &[u8],                           // ocsp_response
        _: SystemTime,                      // now
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn get_server_certificate(domain: &str, port: u32) -> Result<Vec<u8>, RATLSError> {
    let root_store = rustls::RootCertStore::empty();

    let mut socket = std::net::TcpStream::connect(format!("{domain}:{port}"))
        .map_err(|_| RATLSError::ConnectionError)?;

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(NoVerifier));

    let rc_config = std::sync::Arc::new(config);
    let dns_name = domain.try_into().map_err(|_| RATLSError::DNSNameError)?;
    let mut client = rustls::ClientConnection::new(rc_config, dns_name)
        .map_err(|_| RATLSError::ConnectionError)?;
    let mut stream = rustls::Stream::new(&mut client, &mut socket);
    stream
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .unwrap();

    let certificates = client
        .peer_certificates()
        .ok_or(RATLSError::ServerCertificateError)?;

    Ok(certificates
        .get(0)
        .ok_or(RATLSError::ServerCertificateError)?
        .as_ref()
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn it_works() {
        let server_cert = get_server_certificate("self-signed.badssl.com", 443).unwrap();

        let b64_server_cert = r#"
        MIIDeTCCAmGgAwIBAgIJAKL5ZETgtiFQMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
        BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
        c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0y
        MzA0MjQwMDAxNDVaFw0yNTA0MjMwMDAxNDVaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
        VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK
        DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB
        BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2
        PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW
        hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A
        xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve
        ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY
        QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T
        BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI
        hvcNAQELBQADggEBAJqRSkgOf5GHCJzljWQg9D+1LEuByYyQfNzGJb+TZkPpxNEw
        6gbt3vbQfWBx9WQ6995XjdjM6N6l5DO8p0Sp70OHHQ9Lt2N7PC7I5YhJFObkMyza
        sRuLWTzlYShLvSRGQFC/Ky4hTbpzlZA5TADG1weajSlIBLo6UGkQaGk4xG4zhIKA
        PhvsFZsayLexJ1DCql0XAiNnknTfX8FRMI9Ezsj0XeZ8ZD8ouLGYwbTezcYnE/uI
        0Y/ayROwdd+Ny4N6McsEE+KOxS8Xe+LU4X3MEHSXcmT8ht/xTyxQ2JjzHtS6eHjO
        lJON+7kLWv6kgtYf9jHJDsNMPLis6RbUYdkeP5A=
        "#
        .replace(['\n', ' '], "");
        let expected_server_cert = general_purpose::STANDARD.decode(b64_server_cert).unwrap();
        assert_eq!(expected_server_cert, server_cert);
        let (_rem, cert) = x509_parser::parse_x509_certificate(&server_cert).unwrap();
        println!("{:?}", cert);
    }
}

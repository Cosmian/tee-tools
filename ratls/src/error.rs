#[derive(Debug)]
pub enum RATLSError {
    ConnectionError,
    DNSNameError,
    ServerCertificateError,
}

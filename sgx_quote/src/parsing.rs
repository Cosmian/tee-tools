use crate::{
    error::Error,
    quote::{
        AuthData, CertificationData, EcdsaSigData, Quote, QuoteHeader, ReportBody, QUOTE_BODY_SIZE,
        QUOTE_ECDSA_SIG_DATA_SIZE, QUOTE_HEADER_SIZE,
    },
};

use log::debug;

use scroll::Pread;

pub(crate) fn parse_quote_header(raw_quote: &[u8]) -> Result<QuoteHeader, Error> {
    raw_quote
        .pread_with::<QuoteHeader>(0, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse quote header failed: {e:?}")))
}

pub(crate) fn parse_report_body(raw_quote: &[u8]) -> Result<ReportBody, Error> {
    raw_quote
        .pread_with::<ReportBody>(QUOTE_HEADER_SIZE, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse report body failed: {e:?}")))
}

pub(crate) fn parse_quote_body(raw_quote: &[u8]) -> Result<Quote, Error> {
    Ok(Quote {
        header: parse_quote_header(raw_quote)?,
        report_body: parse_report_body(raw_quote)?,
    })
}

pub(crate) fn parse_ecdsa_sig_data(raw_quote: &[u8]) -> Result<EcdsaSigData, Error> {
    raw_quote
        // shift 4 bytes for the signature_data_len (u32)
        .pread_with::<EcdsaSigData>(QUOTE_BODY_SIZE + 4, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse auth data failed: {e:?}")))
}

pub(crate) fn parse_auth_and_cert(
    raw_quote: &[u8],
) -> Result<(AuthData, CertificationData), Error> {
    let offset = &mut (QUOTE_BODY_SIZE + 4 + QUOTE_ECDSA_SIG_DATA_SIZE);
    let qe_auth_data_len = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse QE auth data length failed: {e:?}")))?;
    let mut qe_auth_data: Vec<u8> = vec![0; qe_auth_data_len as usize];
    raw_quote.gread_inout(offset, &mut qe_auth_data)?;
    assert!(
        qe_auth_data.len() == qe_auth_data_len as usize,
        "unexpected qe_auth_data_len"
    );

    let certification_data_type = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| {
            Error::InvalidFormat(format!("Parse certification data type failed: {e:?}"))
        })?;
    debug!("certification_data_type: {}", certification_data_type);

    let certification_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| {
            Error::InvalidFormat(format!("Parse certification data length failed: {e:?}"))
        })?;
    let mut certification_data: Vec<u8> = vec![0; certification_data_len as usize];
    raw_quote.gread_inout(offset, &mut certification_data)?;
    assert!(
        certification_data.len() == certification_data_len as usize,
        "unexpected certification_data_len"
    );

    Ok((
        AuthData {
            auth_data: qe_auth_data,
        },
        CertificationData {
            cert_key_type: certification_data_type,
            certification_data,
        },
    ))
}

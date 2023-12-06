use crate::{error::Error, TDX_GUEST_PATH};

use crate::REPORT_DATA_SIZE;
use nix::ioctl_readwrite;
use std::{fs, os::fd::AsRawFd, ptr};

const TDX_REPORT_LEN: usize = 1024;
const TDX_QUOTE_LEN: usize = 4 * 4096;

#[repr(C)]
pub struct TdxReportReq {
    reportdata: [u8; REPORT_DATA_SIZE], // User buffer with REPORTDATA to be included into TDREPORT
    tdreport: [u8; TDX_REPORT_LEN], // User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT]
}
pub enum TdxOperation {
    TdxGetTdReport = 1,
    TdxGetQuote = 2,
}

#[repr(C)]
struct TdxQuoteHdr {
    version: u64,              // Quote version, filled by TD
    status: u64,               // Status code of Quote request, filled by VMM
    in_len: u32,               // Length of TDREPORT, filled by TD
    out_len: u32,              // Length of Quote, filled by VMM
    data: [u8; TDX_QUOTE_LEN], // Actual Quote data or TDREPORT on input
}

#[repr(C)]
pub struct TdxQuoteReq {
    buf: u64, // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
    len: u64, // Length of the Quote buffer
}

/// Get the report of the TDX
fn get_td_report(user_report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, Error> {
    let device_node = fs::File::options()
        .read(true)
        .write(true)
        .open(TDX_GUEST_PATH)?;

    //prepare get TDX report request data
    let mut request = TdxReportReq {
        reportdata: [0; REPORT_DATA_SIZE],
        tdreport: [0; TDX_REPORT_LEN],
    };
    request.reportdata.copy_from_slice(&user_report_data[..]);

    //build the operator code
    ioctl_readwrite!(
        get_report_ioctl,
        b'T',
        TdxOperation::TdxGetTdReport,
        TdxReportReq
    );

    //apply the ioctl command
    unsafe {
        get_report_ioctl(
            device_node.as_raw_fd(),
            ptr::addr_of!(request) as *mut TdxReportReq,
        )?;
    }

    Ok(request.tdreport.to_vec())
}

/// Get the quote of the TDX
pub(crate) fn _get_quote(user_report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, Error> {
    // Retrieve TDX report
    let report_data_vec = get_td_report(user_report_data)?;
    let report_data_array: [u8; TDX_REPORT_LEN] = report_data_vec
        .try_into()
        .map_err(|_| Error::InvalidFormat("Wrong TDX report format: bad size".to_owned()))?;

    let device_node = fs::File::options()
        .read(true)
        .write(true)
        .open(TDX_GUEST_PATH)?;

    // Build quote generation request header
    let mut quote_header = TdxQuoteHdr {
        version: 1,
        status: 0,
        in_len: TDX_REPORT_LEN as u32,
        out_len: 0,
        data: [0; TDX_QUOTE_LEN],
    };

    quote_header.data[0..TDX_REPORT_LEN].copy_from_slice(&report_data_array[..]);

    let request = TdxQuoteReq {
        buf: ptr::addr_of!(quote_header) as u64,
        len: TDX_QUOTE_LEN as u64,
    };

    // Build the operator code and apply the ioctl command
    ioctl_readwrite!(
        get_quote_ioctl,
        b'T',
        TdxOperation::TdxGetQuote,
        TdxQuoteReq
    );

    unsafe {
        get_quote_ioctl(
            device_node.as_raw_fd(),
            ptr::addr_of!(request) as *mut TdxQuoteReq,
        )?
    };

    if quote_header.status != 0 {
        if quote_header.status == 0xffffffffffffffff {
            return Err(Error::DriverError(
                "The device driver return busy".to_owned(),
            ));
        } else if quote_header.status == 0x8000000000000001 {
            return Err(Error::DriverError(
                "Request feature is not supported".to_owned(),
            ));
        } else if quote_header.out_len == 0 || quote_header.out_len > (TDX_QUOTE_LEN as u32) {
            return Err(Error::DriverError(format!(
                "Invalid Quote size {} (not in [0;{}])",
                quote_header.out_len, TDX_QUOTE_LEN
            )));
        }

        return Err(Error::DriverError(format!(
            "Unexpected error with status {}",
            quote_header.status
        )));
    }

    Ok(quote_header.data[..(quote_header.out_len as usize)].to_vec())
}

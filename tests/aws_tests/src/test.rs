use sev_quote::is_sev;
use tdx_quote::is_tdx;

#[test]
fn is_aws_cvm() {
    if is_sev() {
        println!("Running in AWS AMD SEV environment");
    } else {
        panic!("Not running in a supported AWS CVM environment");
    }
}

#[test]
fn get_and_parse_aws_quote() {
    let user_report_data: [u8; 64] = [0u8; 64];

    if is_sev() {
        let quote =
            sev_quote::quote::get_quote(&user_report_data).expect("Failed to get SNP quote");
        let quote = sev_quote::quote::Quote::try_from(quote).expect("Failed to parse SNP quote");
        println!("SEV Quote: {:?}", quote);
    } else if is_tdx() {
        let quote =
            tdx_quote::quote::get_quote(&user_report_data).expect("Failed to get TDX quote");
        let (quote, _) = tdx_quote::quote::parse_quote(&quote).expect("Failed to parse TDX quote");
        println!("TDX Quote: {:?}", quote);
    } else {
        panic!("Not running in a supported AWS CVM environment");
    }
}

#[test]
fn verify_aws_quote() {
    let user_report_data: [u8; 64] = [0u8; 64];
    if tee_attestation::is_running_inside_tee() {
        let quote =
            tee_attestation::get_quote(Some(&user_report_data)).expect("Failed to get quote");
        tee_attestation::verify_quote(&quote, None).expect("Failed to verify quote");
    } else {
        panic!("Not running in a supported AWS CVM environment");
    }
}

#[test]
fn is_az_cvm() {
    if let Some(report_type) = azure_cvm::is_az_cvm() {
        println!(
            "Running in Azure CVM environment with TEE: {:?}",
            report_type
        );
    } else {
        panic!("Not running in Azure CVM environment");
    }
}

#[test]
fn get_and_parse_az_quote() {
    if let Some(report_type) = azure_cvm::is_az_cvm() {
        let raw_hcl_report = azure_cvm::tpm::get_hcl_report().expect("Failed to get HCL report");
        let hcl_report =
            azure_cvm::HclReport::new(raw_hcl_report).expect("Failed to parse HCL report");

        match report_type {
            azure_cvm::ReportType::Tdx => {
                let td_report: azure_cvm::attestation_report::TdReport =
                    hcl_report.try_into().expect("Failed to parse TD quote");
                let quote =
                    azure_cvm::imds::get_td_quote(&td_report).expect("Failed to get TD quote");
                println!("TD Quote: {:?}", quote);
            }
            azure_cvm::ReportType::Snp => {
                let quote = azure_cvm::get_snp_quote(hcl_report).expect("Failed to get SNP quote");
                let quote =
                    sev_quote::quote::Quote::try_from(quote).expect("Failed to convert SNP quote");
                println!("SNP Quote: {:?}", quote);
            }
        }
    } else {
        panic!("Not running in Azure CVM environment");
    }
}

#[test]
fn verify_az_quote() {
    let user_report_data: [u8; 64] = [0u8; 64];
    if let Ok(tee_type) = tee_attestation::guess_tee() {
        assert!(
            matches!(
                tee_type,
                tee_attestation::TeeType::AzSev | tee_attestation::TeeType::AzTdx
            ),
            "TEE type is not Azure SEV or TDX"
        );
        let quote =
            tee_attestation::get_quote(Some(&user_report_data)).expect("Failed to get quote");
        tee_attestation::verify_quote(&quote, None).expect("Failed to verify quote");
    } else {
        panic!("Not running in a supported Azure CVM environment");
    }
}

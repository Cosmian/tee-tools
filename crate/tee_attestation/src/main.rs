use tee_attestation::{get_quote, guess_tee, TeeType};

fn main() {
    let tee_type = guess_tee().unwrap();
    let raw_quote = get_quote(None).unwrap();

    match tee_type {
        TeeType::AzSev | TeeType::Sev => {
            let quote = sev_quote::quote::parse_quote(&raw_quote).unwrap();
            let filename = "snp_report.bin";
            std::fs::write(filename, raw_quote).unwrap();
            println!(
                "AMD SEV-SNP found: report saved in {}\n{}",
                filename, quote.report
            );
        }
        TeeType::Tdx | TeeType::AzTdx => {
            let (quote, _) = tdx_quote::quote::parse_quote(&raw_quote).unwrap();
            let filename = "tdx_quote.bin";
            std::fs::write(filename, raw_quote).unwrap();
            println!("Intel TDX found: quote saved in {}\n{}", filename, quote);
        }
        TeeType::Sgx => {
            let (quote, _, _, _) = sgx_quote::quote::parse_quote(&raw_quote).unwrap();
            let filename = "sgx_quote.bin";
            std::fs::write(filename, raw_quote).unwrap();
            println!("Intel SGX found: quote saved in {}\n{}", filename, quote);
        }
    }
}

use tee_attestation::verify_quote;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let report = args.get(1).expect("attestation report is missing!");
    let report = std::fs::read(report).expect("can't read file content");
    verify_quote(&report, None).unwrap();
}

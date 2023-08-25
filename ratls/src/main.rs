use anyhow::Result;
use ratls::generate_ratls_cert;

fn main() -> Result<()> {
    generate_ratls_cert(
        "FR",
        "IDF",
        "Paris",
        "Cosmian",
        "common.name",
        vec!["name1", "0.0.0.0", "name2"],
        365,
        "password",
    )?;
    Ok(())
}

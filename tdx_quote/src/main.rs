use std::{error::Error, fs, io::Write};

use tdx_quote::quote::{get_quote, parse_quote};

fn main() -> Result<(), Box<dyn Error>> {
    let quote = get_quote(b"0123456789abcdef012345678789abcdef0123456789abcdef")?;
    let mut f = fs::File::create("quote.dat")?;
    f.write_all(quote.as_slice())?;

    let (quote, sig) = parse_quote(&quote)?;
    println!("{quote} {sig}");

    Ok(())
}

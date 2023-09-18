use anyhow::Result;

use clap::{Parser, Subcommand};

pub mod fetch;
pub mod generate;
pub mod key;
pub mod verify;

use fetch::FetchArgs;
use generate::GenerateArgs;
use key::KeyArgs;
use verify::VerifyArgs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,
}

#[derive(Subcommand)]
enum CliCommands {
    Generate(GenerateArgs),
    Fetch(FetchArgs),
    Key(KeyArgs),
    Verify(VerifyArgs),
}

fn main() -> Result<()> {
    let opts = Cli::parse();

    match opts.command {
        CliCommands::Generate(args) => args.run(),
        CliCommands::Fetch(args) => args.run(),
        CliCommands::Key(args) => args.run(),
        CliCommands::Verify(args) => args.run(),
    }?;

    Ok(())
}

use anyhow::Result;

use clap::{Parser, Subcommand};

pub mod generate;
pub mod verify;

use generate::GenerateArgs;
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
    Verify(VerifyArgs),
}

fn main() -> Result<()> {
    let opts = Cli::parse();

    match opts.command {
        CliCommands::Generate(args) => args.run(),
        CliCommands::Verify(args) => args.run(),
    }?;

    Ok(())
}

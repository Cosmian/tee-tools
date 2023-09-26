use anyhow::Result;

use clap::{Parser, Subcommand};

pub mod fetch;
#[cfg(target_os = "linux")]
pub mod generate;
#[cfg(target_os = "linux")]
pub mod key;
pub mod verify;

use fetch::FetchArgs;
#[cfg(target_os = "linux")]
use generate::GenerateArgs;
#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    Generate(GenerateArgs),
    Fetch(FetchArgs),
    #[cfg(target_os = "linux")]
    Key(KeyArgs),
    Verify(VerifyArgs),
}

fn main() -> Result<()> {
    let opts = Cli::parse();

    match opts.command {
        #[cfg(target_os = "linux")]
        CliCommands::Generate(args) => args.run(),
        CliCommands::Fetch(args) => args.run(),
        #[cfg(target_os = "linux")]
        CliCommands::Key(args) => args.run(),
        CliCommands::Verify(args) => args.run(),
    }?;

    Ok(())
}

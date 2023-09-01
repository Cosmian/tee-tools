use anyhow::Result;

use clap::{Parser, Subcommand};

pub mod generate;
pub mod key;
pub mod verify;

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
    Key(KeyArgs),
    Verify(VerifyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Cli::parse();

    match opts.command {
        CliCommands::Generate(args) => args.run(),
        CliCommands::Key(args) => args.run(),
        CliCommands::Verify(args) => args.run().await,
    }?;

    Ok(())
}

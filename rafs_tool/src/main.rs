use anyhow::Result;

use clap::{Parser, Subcommand};
use decrypt::DecryptArgs;
use encrypt::EncryptArgs;
use init::InitArgs;
use proxy::ProxyArgs;

pub mod common;
pub mod decrypt;
pub mod encrypt;
pub mod init;
pub mod proxy;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,
}

#[derive(Subcommand)]
enum CliCommands {
    Init(InitArgs),
    Proxy(ProxyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

fn main() -> Result<()> {
    let opts = Cli::parse();

    match opts.command {
        CliCommands::Init(args) => args.run(),
        CliCommands::Proxy(args) => args.run(),
        CliCommands::Encrypt(args) => args.run(),
        CliCommands::Decrypt(args) => args.run(),
    }?;

    Ok(())
}

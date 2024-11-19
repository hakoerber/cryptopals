use std::fs;

use lib::{aes, base64, Error};

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Decrypt(DecryptArgs),
}

#[derive(ValueEnum, Clone, Debug)]
enum Encoding {
    Base64,
}

#[derive(ValueEnum, Clone, Debug)]
enum Mode {
    Ecb,
}

#[derive(Args, Debug)]
struct DecryptArgs {
    #[arg(long)]
    key: String,

    #[arg(long)]
    path: String,

    #[arg(long)]
    encoding: Encoding,

    #[arg(long)]
    mode: Mode,
}

#[expect(clippy::print_stdout, reason = "main function")]
fn main() -> Result<(), Error> {
    let args = Cli::parse();

    match args.command {
        Commands::Decrypt(decrypt_args) => {
            let input = fs::read_to_string(decrypt_args.path)?;

            let decoded = match decrypt_args.encoding {
                Encoding::Base64 => base64::decode_str(&input)?,
            };

            let key = decrypt_args.key.as_bytes();

            let key: [u8; 16] = key
                .try_into()
                .map_err(|_e| Error("invalid key size".to_owned()))?;

            let key = aes::Key128::from_bytes(key);

            let decrypted = match decrypt_args.mode {
                Mode::Ecb => aes::decrypt_ecb(&decoded, key),
            };

            println!(
                "{}",
                String::from_utf8(decrypted).expect("decryption produced invalid utf-8")
            );
        }
    }

    Ok(())
}

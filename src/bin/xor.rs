use std::fs;

use lib::{xor, Error};

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(long)]
    key: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Input(InputArgs),
    File(FileArgs),
}

#[derive(Args, Debug)]
struct InputArgs {
    #[arg(help = "the input to decode")]
    input: String,
}

#[derive(Args, Debug)]
struct FileArgs {
    #[arg(long, help = "a path to the file to read strings from")]
    path: String,
}

fn main() -> Result<(), Error> {
    let args = Cli::parse();

    let data = match args.command {
        Commands::File(args) => fs::read_to_string(args.path)?,
        Commands::Input(args) => args.input,
    };

    let key = args.key;

    println!(
        "{}",
        String::from_utf8(xor::xor_repeating(data.as_bytes(), key.as_bytes())).unwrap()
    );

    Ok(())
}

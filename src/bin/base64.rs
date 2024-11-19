use std::io;

use clap::Parser;

use lib::{base64, Error};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(long, help = "assume input is hex data")]
    hex: bool,
}

#[expect(clippy::print_stdout, reason = "main function")]
fn main() -> Result<(), Error> {
    let args = Args::parse();

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    if args.hex {
        println!("{}", lib::hex_string_to_base64_string(buffer.trim())?);
    } else {
        println!("{}", base64::str_to_base64_string(buffer.trim()));
    }

    Ok(())
}

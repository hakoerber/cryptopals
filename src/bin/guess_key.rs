use std::{cmp, fs};

use lib::{hex, text, xor, Error};

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
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

#[expect(clippy::print_stdout, reason = "main function")]
fn main() -> Result<(), Error> {
    const CANDIDATE_COUNT: usize = 10;

    let args = Cli::parse();

    match args.command {
        Commands::Input(args) => {
            let input: Vec<u8> = hex::parse_hex_string(&args.input)?;
            let candidates =
                xor::guess_single_xor_key::<CANDIDATE_COUNT>(&input, text::score_english_plaintext)
                    .expect("did not receive a single candidate");

            for candidate in candidates {
                println!(
                    "| score {:08} | key 0x{:02x} | {}",
                    candidate.score, candidate.key, candidate.text
                );
            }
        }
        Commands::File(args) => {
            #[derive(Debug, Clone)]
            struct Position {
                candidate: xor::Candidate,
                line_nr: usize,
                line: String,
            }

            impl Eq for Position {}

            impl Ord for Position {
                fn cmp(&self, other: &Self) -> cmp::Ordering {
                    self.candidate.cmp(&other.candidate)
                }
            }

            impl PartialEq for Position {
                fn eq(&self, other: &Self) -> bool {
                    self.candidate.eq(&other.candidate)
                }
            }

            impl PartialOrd for Position {
                fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }

            let input = fs::read_to_string(args.path)?;

            let mut positions = Vec::new();

            for (line_nr, line) in input.lines().enumerate() {
                let input = hex::parse_hex_string(line)?;

                let best_candidate =
                    xor::guess_single_xor_key::<1>(&input, text::score_english_plaintext);
                if let Some(candidate) = best_candidate {
                    let candidate = candidate[0].clone();

                    positions.push(Position {
                        line: line.to_owned(),
                        line_nr,
                        candidate,
                    });
                }
            }

            positions.sort();
            positions.reverse();

            println!("10 best candidates:");
            for position in positions.iter().take(10) {
                println!(
                    "| score {:08} | line {:03} | key 0x{:02x} | {} | {}",
                    position.candidate.score,
                    position.line_nr,
                    position.candidate.key,
                    position.line,
                    position.candidate.text
                );
            }
        }
    }

    Ok(())
}

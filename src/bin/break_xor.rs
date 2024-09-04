use std::{fs, ops::RangeInclusive};

use lib::{base64, text, xor, Error};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(long, help = "a path to the file to read")]
    base64_path: String,
}

fn main() -> Result<(), Error> {
    const ANALYZE_CHUNK_DISTANCES: usize = 5;
    const KEYSIZE_RANGE: RangeInclusive<usize> = 2..=50;
    const SELECT_KEYSIZE_COUNT: usize = 4;

    let args = Cli::parse();

    #[derive(Debug, PartialOrd, PartialEq)]
    struct KeysizeCandidate {
        hamming_distance: f32,
        keysize: usize,
    }

    let mut keysize_candidates = Vec::new();

    let input = fs::read_to_string(args.base64_path)?;
    let input = base64::decode_str(&input)?;

    for keysize in KEYSIZE_RANGE {
        let mut hamming_distance = 0.0;
        for i in 0..ANALYZE_CHUNK_DISTANCES {
            let chunk_hamming_distance = text::hamming_bits(
                &input[i * keysize..(i + 1) * keysize],
                &input[(i + 1) * keysize..(i + 2) * keysize],
            );
            hamming_distance += chunk_hamming_distance as f32;
        }

        hamming_distance /= keysize as f32;

        keysize_candidates.push(KeysizeCandidate {
            hamming_distance,
            keysize,
        })
    }

    keysize_candidates.sort_by(|a, b| a.hamming_distance.partial_cmp(&b.hamming_distance).unwrap());
    let keysize_candidates: Vec<KeysizeCandidate> = keysize_candidates
        .into_iter()
        .take(SELECT_KEYSIZE_COUNT)
        .collect();

    println!("most promising keysize candidates:");
    for candidate in keysize_candidates.iter() {
        println!("{:?}", candidate);
    }

    for candidate in keysize_candidates.iter().take(SELECT_KEYSIZE_COUNT) {
        let keysize = candidate.keysize;
        println!("{}", "=".repeat(100));
        println!("trying keysize {keysize}");

        let mut stripes: Vec<Vec<u8>> = vec![vec![]; keysize];

        for block in input.chunks(keysize) {
            for i in 0..keysize {
                let block = block.get(i);
                if let Some(block) = block {
                    stripes[i].push(*block);
                }
            }
        }

        let mut key: Vec<u8> = Vec::new();

        for stripe in stripes {
            let best_candidate =
                xor::guess_single_xor_key::<1>(&stripe, text::score_english_plaintext).unwrap()[0]
                    .clone();

            key.push(best_candidate.key);
        }

        println!("key {} looks good", String::from_utf8(key.clone()).unwrap());
        println!("{}", ".".repeat(100));
        let mut cleartext = String::from_utf8(xor::xor_repeating(&input, &key)).unwrap();
        cleartext.truncate(500);
        println!("{}", cleartext);
    }

    Ok(())
}

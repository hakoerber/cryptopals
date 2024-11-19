use std::{fs, ops::RangeInclusive};

use lib::{base64, text, xor, Error};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(long, help = "a path to the file to read")]
    base64_path: String,
}

#[expect(clippy::print_stdout, reason = "main function")]
#[expect(clippy::use_debug, reason = "debug output is just for debug logging")]
fn main() -> Result<(), Error> {
    const ANALYZE_CHUNK_DISTANCES: usize = 5;
    const KEYSIZE_RANGE: RangeInclusive<usize> = 2..=50;
    const SELECT_KEYSIZE_COUNT: usize = 4;

    #[derive(Debug, PartialOrd, PartialEq)]
    struct KeysizeCandidate {
        hamming_distance: f32,
        keysize: usize,
    }

    let args = Cli::parse();

    let mut keysize_candidates = Vec::new();

    let input = fs::read_to_string(args.base64_path)?;
    let input = base64::decode_str(&input)?;

    assert!(
        input.len()
            >= (ANALYZE_CHUNK_DISTANCES
                .checked_add(2)
                .expect("ANALYZE_CHUNK_DISTANCES too large"))
            .checked_mul(*KEYSIZE_RANGE.end())
            .expect("constants too big"),
        "input too short for analysis"
    );

    #[expect(clippy::assertions_on_constants, reason = "they may change")]
    {
        assert!(
            ANALYZE_CHUNK_DISTANCES < usize::MAX - 2,
            "ANALYZE_CHUNK_DISTANCES too large"
        );
    }

    assert!(*KEYSIZE_RANGE.end() < usize::MAX, "KEYSIZE_RANGE too large");

    #[expect(
        clippy::float_arithmetic,
        clippy::cast_precision_loss,
        clippy::as_conversions,
        reason = "the float ops do not have to be precise"
    )]
    #[expect(
        clippy::indexing_slicing,
        reason = "checked for input being long enough above"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "checked for proper values of the constants above"
    )]
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
        });
    }

    keysize_candidates.sort_by(|a, b| {
        a.hamming_distance
            .partial_cmp(&b.hamming_distance)
            .expect("none of those values are NaN")
    });
    let keysize_candidates: Vec<KeysizeCandidate> = keysize_candidates
        .into_iter()
        .take(SELECT_KEYSIZE_COUNT)
        .collect();

    println!("most promising keysize candidates:");
    for candidate in &keysize_candidates {
        println!("{candidate:?}");
    }

    for candidate in keysize_candidates.iter().take(SELECT_KEYSIZE_COUNT) {
        let keysize = candidate.keysize;
        println!("{}", "=".repeat(100));
        println!("trying keysize {keysize}");

        let mut stripes: Vec<Vec<u8>> = vec![vec![]; keysize];

        for block in input.chunks(keysize) {
            for (i, stripe) in stripes.iter_mut().enumerate().take(keysize) {
                let block = block.get(i);
                if let Some(block) = block {
                    stripe.push(*block);
                }
            }
        }

        let mut key: Vec<u8> = Vec::new();

        for stripe in stripes {
            let best_candidate =
                xor::guess_single_xor_key::<1>(&stripe, text::score_english_plaintext)
                    .expect("received not a single candidate")[0]
                    .clone();

            key.push(best_candidate.key);
        }

        println!(
            "key {} looks good",
            String::from_utf8(key.clone()).expect("received non-utf8 xored output")
        );
        println!("{}", ".".repeat(100));
        let mut cleartext = String::from_utf8(xor::xor_repeating(&input, &key))
            .expect("received non-utf8 xored output");
        cleartext.truncate(500);
        println!("{cleartext}");
    }

    Ok(())
}

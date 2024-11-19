pub fn score_english_plaintext(text: &str) -> usize {
    // https://en.wikipedia.org/wiki/Letter_frequency
    let frequent_letter_count = text
        .chars()
        .filter(|c| matches!((*c).to_ascii_lowercase(), 'e' | 't' | 'a' | 'o' | 'i' | 'n'))
        .count();

    frequent_letter_count
}

pub fn score_english_plaintext_2(text: &str) -> usize {
    // https://en.wikipedia.org/wiki/Letter_frequency
    let letter_count = text.chars().filter(char::is_ascii_alphabetic).count();

    let frequent_letter_count = text
        .chars()
        .filter(|c| matches!((*c).to_ascii_lowercase(), 'e' | 't' | 'a' | 'o' | 'i' | 'n'))
        .count();

    let symbol_count = text.chars().filter(char::is_ascii_punctuation).count();

    let control_count = text.chars().filter(char::is_ascii_control).count();

    frequent_letter_count
        .checked_add(letter_count)
        .expect("usize overflow")
        .saturating_sub(symbol_count)
        .saturating_sub(control_count.checked_add(100).expect("usize overflow"))
}

pub fn hamming_bits(t1: &[u8], t2: &[u8]) -> usize {
    assert_eq!(t1.len(), t2.len(), "t1 and t2 have to be the same size");

    t1.iter()
        .zip(t2.iter())
        .map(|(b1, b2)| {
            let mut diffs = 0;
            for i in 0..8_u8 {
                if 0x01 & (b1 >> i) != 0x01 & (b2 >> i) {
                    #[expect(
                        clippy::arithmetic_side_effects,
                        reason = "usize cannot overflow as the loop iterates a max of 8 times"
                    )]
                    {
                        diffs += 1;
                    }
                }
            }
            diffs
        })
        .sum()
}

pub fn hamming_bits_str(t1: &str, t2: &str) -> usize {
    let t1 = t1.as_bytes();
    let t2 = t2.as_bytes();
    hamming_bits(t1, t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_cryptopals_example() {
        assert_eq!(hamming_bits_str("this is a test", "wokka wokka!!!"), 37);
    }
}

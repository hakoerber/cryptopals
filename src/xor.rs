use std::cmp;

use crate::ascii;

pub fn xor_matching(d1: &[u8], d2: &[u8]) -> Vec<u8> {
    if d1.len() != d2.len() {
        panic!("data has to have the same length")
    }

    d1.iter().enumerate().map(|(i, r)| *r ^ d2[i]).collect()
}

pub fn xor_single(data: &[u8], operand: u8) -> Vec<u8> {
    data.iter().map(|r| *r ^ operand).collect()
}

pub fn xor_repeating(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty());
    data.iter()
        .zip(key.iter().cycle())
        .map(|(d1, d2)| d1 ^ d2)
        .collect()
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: u8,
    pub text: String,
    pub score: usize,
}

impl Eq for Candidate {}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.score.cmp(&other.score)
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.score.eq(&other.score)
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// this may return None when not enough potential cleartexts are valid
/// ascii
pub fn guess_single_xor_key<const C: usize>(
    input: &[u8],
    scorer: impl Fn(&str) -> usize,
) -> Option<[Candidate; C]> {
    assert!(C < u8::MAX as usize);

    let mut candidates = Vec::new();

    for i in 0..=u8::MAX {
        let result = xor_single(input, i);

        if let Some(text) = ascii::from_bytes(&result) {
            let score = scorer(&text);
            candidates.push(Candidate {
                key: i,
                text,
                score,
            })
        }
    }

    candidates.sort();
    candidates.reverse();
    candidates.truncate(C);
    candidates.try_into().ok()
}

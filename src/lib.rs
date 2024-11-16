mod error;

pub use error::Error;

pub mod aes;
pub mod ascii;
pub mod base64;
pub mod hex;
pub mod text;
pub mod xor;

pub fn hex_string_to_base64_string(input: &str) -> Result<String, Error> {
    Ok(base64::bytes_to_base64_string(&hex::parse_hex_string(
        input,
    )?))
}

pub fn xor_hex_strings(s1: &str, s2: &str) -> Result<String, Error> {
    let d1 = hex::parse_hex_string(s1)?;
    let d2 = hex::parse_hex_string(s2)?;

    if d1.len() != d2.len() {
        return Err(Error("string length mismatch".to_owned()));
    }

    let result = xor::xor_matching(&d1, &d2);

    Ok(hex::to_str(&result))
}

pub fn xor_string_repeating(data: &str, key: &str) -> String {
    let data = data.as_bytes();
    let key = key.as_bytes();

    let result = xor::xor_repeating(data, key);

    hex::to_str(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_example_cryptopals() {
        assert_eq!(
            hex_string_to_base64_string("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn xor_two_strings_example_cryptopals() {
        assert_eq!(
            xor_hex_strings(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            )
            .unwrap(),
            "746865206b696420646f6e277420706c6179"
        )
    }

    #[test]
    fn xor_repeating_example_cryptopals() {
        assert_eq!(xor_string_repeating("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    }
}

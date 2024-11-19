use super::Error;

#[derive(Debug, PartialEq, Eq)]
struct Base64Char(char);

impl From<Base64Char> for char {
    fn from(value: Base64Char) -> Self {
        value.0
    }
}

impl Base64Char {
    const PLACEHOLDER: char = '=';

    const fn placeholder() -> Self {
        Self(Self::PLACEHOLDER)
    }

    fn sextet_value(value: char) -> Result<Option<u8>, Error> {
        Ok(match value {
            'A' => Some(0),
            'B' => Some(1),
            'C' => Some(2),
            'D' => Some(3),
            'E' => Some(4),
            'F' => Some(5),
            'G' => Some(6),
            'H' => Some(7),
            'I' => Some(8),
            'J' => Some(9),
            'K' => Some(10),
            'L' => Some(11),
            'M' => Some(12),
            'N' => Some(13),
            'O' => Some(14),
            'P' => Some(15),
            'Q' => Some(16),
            'R' => Some(17),
            'S' => Some(18),
            'T' => Some(19),
            'U' => Some(20),
            'V' => Some(21),
            'W' => Some(22),
            'X' => Some(23),
            'Y' => Some(24),
            'Z' => Some(25),
            'a' => Some(26),
            'b' => Some(27),
            'c' => Some(28),
            'd' => Some(29),
            'e' => Some(30),
            'f' => Some(31),
            'g' => Some(32),
            'h' => Some(33),
            'i' => Some(34),
            'j' => Some(35),
            'k' => Some(36),
            'l' => Some(37),
            'm' => Some(38),
            'n' => Some(39),
            'o' => Some(40),
            'p' => Some(41),
            'q' => Some(42),
            'r' => Some(43),
            's' => Some(44),
            't' => Some(45),
            'u' => Some(46),
            'v' => Some(47),
            'w' => Some(48),
            'x' => Some(49),
            'y' => Some(50),
            'z' => Some(51),
            '0' => Some(52),
            '1' => Some(53),
            '2' => Some(54),
            '3' => Some(55),
            '4' => Some(56),
            '5' => Some(57),
            '6' => Some(58),
            '7' => Some(59),
            '8' => Some(60),
            '9' => Some(61),
            '+' => Some(62),
            '/' => Some(63),
            Self::PLACEHOLDER => None,
            _ => return Err(Error(format!("invalid base64 character: {value}"))),
        })
    }

    fn try_from_sextet(value: u8) -> Result<Self, Error> {
        Ok(match value {
            0 => Self('A'),
            1 => Self('B'),
            2 => Self('C'),
            3 => Self('D'),
            4 => Self('E'),
            5 => Self('F'),
            6 => Self('G'),
            7 => Self('H'),
            8 => Self('I'),
            9 => Self('J'),
            10 => Self('K'),
            11 => Self('L'),
            12 => Self('M'),
            13 => Self('N'),
            14 => Self('O'),
            15 => Self('P'),
            16 => Self('Q'),
            17 => Self('R'),
            18 => Self('S'),
            19 => Self('T'),
            20 => Self('U'),
            21 => Self('V'),
            22 => Self('W'),
            23 => Self('X'),
            24 => Self('Y'),
            25 => Self('Z'),
            26 => Self('a'),
            27 => Self('b'),
            28 => Self('c'),
            29 => Self('d'),
            30 => Self('e'),
            31 => Self('f'),
            32 => Self('g'),
            33 => Self('h'),
            34 => Self('i'),
            35 => Self('j'),
            36 => Self('k'),
            37 => Self('l'),
            38 => Self('m'),
            39 => Self('n'),
            40 => Self('o'),
            41 => Self('p'),
            42 => Self('q'),
            43 => Self('r'),
            44 => Self('s'),
            45 => Self('t'),
            46 => Self('u'),
            47 => Self('v'),
            48 => Self('w'),
            49 => Self('x'),
            50 => Self('y'),
            51 => Self('z'),
            52 => Self('0'),
            53 => Self('1'),
            54 => Self('2'),
            55 => Self('3'),
            56 => Self('4'),
            57 => Self('5'),
            58 => Self('6'),
            59 => Self('7'),
            60 => Self('8'),
            61 => Self('9'),
            62 => Self('+'),
            63 => Self('/'),
            _ => return Err(Error(format!("invalid base64 character: {value}"))),
        })
    }
}

#[expect(
    clippy::identity_op,
    clippy::eq_op,
    clippy::default_numeric_fallback,
    clippy::as_conversions,
    reason = "all bitwise opts, it's fine clippy"
)]
fn encode_three_bytes(b1: u8, b2: u8, b3: u8) -> [Base64Char; 4] {
    // easier to operate on a single u32
    let b = u32::from_be_bytes([b1, b2, b3, 0]);
    let sextet1 = ((b & 0b1111_1100_0000_0000_0000_0000_0000_0000) >> (8 + (24 - 6 * 1))) as u8;
    let sextet2 = ((b & 0b0000_0011_1111_0000_0000_0000_0000_0000) >> (8 + (24 - 6 * 2))) as u8;
    let sextet3 = ((b & 0b0000_0000_0000_1111_1100_0000_0000_0000) >> (8 + (24 - 6 * 3))) as u8;
    let sextet4 = ((b & 0b0000_0000_0000_0000_0011_1111_0000_0000) >> (8 + (24 - 6 * 4))) as u8;

    [
        Base64Char::try_from_sextet(sextet1).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet2).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet3).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet4).expect("invalid base64 value"),
    ]
}

#[expect(
    clippy::identity_op,
    clippy::default_numeric_fallback,
    clippy::as_conversions,
    reason = "all bitwise opts, it's fine clippy"
)]
fn encode_two_bytes(b1: u8, b2: u8) -> [Base64Char; 4] {
    // easier to operate on a single u16
    let b = u16::from_be_bytes([b1, b2]);
    let sextet1 = ((b & 0b1111_1100_0000_0000) >> (16 - (6 * 1))) as u8;
    let sextet2 = ((b & 0b0000_0011_1111_0000) >> (16 - (6 * 2))) as u8;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "truncation cannot happen, look at the bitmask"
    )]
    let sextet3 = ((b & 0b0000_0000_0000_1111) << (16_i8 - (6 * 3)).abs()) as u8;

    [
        Base64Char::try_from_sextet(sextet1).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet2).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet3).expect("invalid base64 value"),
        Base64Char::placeholder(),
    ]
}

#[expect(
    clippy::identity_op,
    clippy::default_numeric_fallback,
    reason = "all bitwise opts, it's fine clippy"
)]
fn encode_one_byte(b1: u8) -> [Base64Char; 4] {
    let sextet1 = (b1 & 0b1111_1100) >> (8 - (6 * 1));
    let sextet2 = (b1 & 0b0000_0011) << (8_i8 - (6 * 2)).abs();

    [
        Base64Char::try_from_sextet(sextet1).expect("invalid base64 value"),
        Base64Char::try_from_sextet(sextet2).expect("invalid base64 value"),
        Base64Char::placeholder(),
        Base64Char::placeholder(),
    ]
}

pub fn bytes_to_base64_string(data: &[u8]) -> String {
    #[expect(
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "we do explicit match against len(), the compiler should be able to figure it out"
    )]
    data.chunks(3)
        .flat_map(|byte_chunk| match byte_chunk.len() {
            1 => encode_one_byte(byte_chunk[0]),
            2 => encode_two_bytes(byte_chunk[0], byte_chunk[1]),
            3 => encode_three_bytes(byte_chunk[0], byte_chunk[1], byte_chunk[2]),
            _ => unreachable!(),
        })
        .map(|base64_char| -> char { base64_char.into() })
        .collect()
}

pub fn str_to_base64_string(input: &str) -> String {
    bytes_to_base64_string(input.as_bytes())
}

#[expect(
    clippy::default_numeric_fallback,
    reason = "all bitwise opts, it's fine clippy"
)]
pub fn decode_str(input: &str) -> Result<Vec<u8>, Error> {
    #[expect(
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "we check for len() explicitly, the compiler should be able to figure it out"
    )]
    Ok(input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<Vec<char>>()
        .chunks(4)
        .map(|chunk| {
            if chunk.len() != 4 {
                return Err(Error("invalid input length".to_owned()));
            }

            let sextet1 = Base64Char::sextet_value(chunk[0])?
                .ok_or_else(|| Error("invalid format, too much padding".to_owned()))?;
            let sextet2 = Base64Char::sextet_value(chunk[1])?
                .ok_or_else(|| Error("invalid format, too much padding".to_owned()))?;
            let sextet3 = Base64Char::sextet_value(chunk[2])?;
            let sextet4 = Base64Char::sextet_value(chunk[3])?;

            if sextet3.is_none() && sextet4.is_some() {
                return Err(Error("invalid padding".to_owned()));
            }

            let byte1 = (sextet1 << 2) | (sextet2 >> 4);
            match sextet3 {
                None => Ok(vec![byte1]),
                Some(sextet3) => {
                    let byte2 = ((sextet2 & 0x0F) << 4) | ((sextet3 & 0b0011_1100) >> 2);
                    match sextet4 {
                        None => Ok(vec![byte1, byte2]),
                        Some(sextet4) => {
                            let byte3 = ((sextet3 & 0b0000_0011) << 6) | sextet4;
                            Ok(vec![byte1, byte2, byte3])
                        }
                    }
                }
            }
        })
        .collect::<Result<Vec<Vec<u8>>, Error>>()?
        .into_iter()
        .flatten()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_triple_byte_encoding() {
        assert_eq!(
            encode_one_byte(0),
            [
                Base64Char('A'),
                Base64Char('A'),
                Base64Char::placeholder(),
                Base64Char::placeholder()
            ]
        );

        assert_eq!(
            encode_two_bytes(0, 0),
            [
                Base64Char('A'),
                Base64Char('A'),
                Base64Char('A'),
                Base64Char::placeholder()
            ]
        );

        assert_eq!(
            encode_three_bytes(0, 0, 0),
            [
                Base64Char('A'),
                Base64Char('A'),
                Base64Char('A'),
                Base64Char('A'),
            ]
        );

        assert_eq!(
            encode_one_byte(0xFF),
            [
                Base64Char('/'),
                Base64Char('w'),
                Base64Char::placeholder(),
                Base64Char::placeholder()
            ]
        );

        assert_eq!(
            encode_two_bytes(0xFF, 0xFF),
            [
                Base64Char('/'),
                Base64Char('/'),
                Base64Char('8'),
                Base64Char::placeholder()
            ]
        );

        assert_eq!(
            encode_three_bytes(0xFF, 0xFF, 0xFF),
            [
                Base64Char('/'),
                Base64Char('/'),
                Base64Char('/'),
                Base64Char('/'),
            ]
        );
    }

    #[test]
    fn example_wikipedia() {
        assert_eq!(
            str_to_base64_string("Polyfon zwitschernd aßen Mäxchens Vögel Rüben, Joghurt und Quark"),
            "UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydCB1bmQgUXVhcms="
        );
    }

    #[test]
    fn example_decode() {
        assert_eq!(
            decode_str("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu").unwrap(),
            "Many hands make light work.".as_bytes()
        );
    }
}

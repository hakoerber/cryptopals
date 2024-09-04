use super::Error;

#[derive(Clone, Copy)]
enum HexChar {
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    A,
    B,
    C,
    D,
    E,
    F,
}

macro_rules! impl_try_from {
    ($type:ty) => {
        impl TryFrom<$type> for HexChar {
            type Error = Error;

            fn try_from(value: $type) -> Result<Self, Self::Error> {
                Ok(match value {
                    0 => Self::D0,
                    1 => Self::D1,
                    2 => Self::D2,
                    3 => Self::D3,
                    4 => Self::D4,
                    5 => Self::D5,
                    6 => Self::D6,
                    7 => Self::D7,
                    8 => Self::D8,
                    9 => Self::D9,
                    10 => Self::A,
                    11 => Self::B,
                    12 => Self::C,
                    13 => Self::D,
                    14 => Self::E,
                    15 => Self::F,
                    _ => return Err(Error(format!("invalid hex value: {value}"))),
                })
            }
        }
    };
}

impl_try_from!(u8);
impl_try_from!(u32);

impl From<HexChar> for char {
    fn from(value: HexChar) -> Self {
        match value {
            HexChar::D0 => '0',
            HexChar::D1 => '1',
            HexChar::D2 => '2',
            HexChar::D3 => '3',
            HexChar::D4 => '4',
            HexChar::D5 => '5',
            HexChar::D6 => '6',
            HexChar::D7 => '7',
            HexChar::D8 => '8',
            HexChar::D9 => '9',
            HexChar::A => 'a',
            HexChar::B => 'b',
            HexChar::C => 'c',
            HexChar::D => 'd',
            HexChar::E => 'e',
            HexChar::F => 'f',
        }
    }
}

impl TryFrom<char> for HexChar {
    type Error = Error;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        value
            .to_digit(16)
            .ok_or_else(|| Error(format!("invalid hex character found: {value}")))?
            .try_into()
    }
}

pub fn parse_hex_string(data: &str) -> Result<Vec<u8>, Error> {
    data.chars()
        .map(|c| -> Result<HexChar, _> { c.try_into() })
        .collect::<Result<Vec<HexChar>, Error>>()?
        .chunks(2)
        .map(|elem| match elem.len() {
            1 => Err(Error("input length not divisible by 2".to_owned())),
            2 => Ok(elem[0] as u8 * 16 + elem[1] as u8),
            _ => unreachable!(),
        })
        .collect()
}

pub fn to_str(data: &[u8]) -> String {
    data.into_iter()
        .flat_map(|b| {
            let upper = (b & 0xF0) >> 4;
            let lower = b & 0x0F;

            let upper: HexChar = upper.try_into().unwrap();
            let lower: HexChar = lower.try_into().unwrap();

            [upper, lower]
        })
        .map(|c| -> char { c.into() })
        .collect()
}

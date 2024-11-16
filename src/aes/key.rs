use std::{fmt, ops::Index};

use super::{gf, SBOX_ENCRYPT};

#[derive(Clone, Copy)]
struct Rcon([u8; 4]);

const ROUND_CONSTANTS: [Rcon; 10] = [
    Rcon([0x01, 0x00, 0x00, 0x00]),
    Rcon([0x02, 0x00, 0x00, 0x00]),
    Rcon([0x04, 0x00, 0x00, 0x00]),
    Rcon([0x08, 0x00, 0x00, 0x00]),
    Rcon([0x10, 0x00, 0x00, 0x00]),
    Rcon([0x20, 0x00, 0x00, 0x00]),
    Rcon([0x40, 0x00, 0x00, 0x00]),
    Rcon([0x80, 0x00, 0x00, 0x00]),
    Rcon([0x1b, 0x00, 0x00, 0x00]),
    Rcon([0x36, 0x00, 0x00, 0x00]),
];

fn rot_word(word: &mut [u8; 4]) {
    let tmp = word[0];
    (*word)[0] = word[1];
    (*word)[1] = word[2];
    (*word)[2] = word[3];
    (*word)[3] = tmp;
}

fn sub_word(word: &mut [u8; 4]) {
    for i in 0..4 {
        (*word)[i] = SBOX_ENCRYPT[word[i] as usize]
    }
}

fn rcon(word: &mut [u8; 4], constant: Rcon) {
    (*word) = gf::add_word(*word, constant.0)
}

macro_rules! impl_keys {
    ($($size:expr),+) => {
        paste::paste! {
            $(
                #[derive(Debug, PartialEq, Eq)]
                pub struct [<Key $size>]([u8; $size / 8]);

                impl [<Key $size>] {
                    pub fn from_bytes(value: [u8; $size / 8]) -> Self {
                        Self(value)
                    }

                    pub fn column(&self, index: usize) -> &[u8; 4] {
                        let count = const {
                            match $size {
                                128 => 4,
                                192 => 6,
                                256 => 8,
                                _ => panic!("unknown key size")
                            }
                        };

                        assert!(index <= count, "index out of range");

                        self.0
                            .get((index * 4)..(index * 4 + 4))
                            .unwrap()
                            .try_into()
                            .unwrap()
                    }
                }
            )+

            $(
                #[derive(Debug, PartialEq, Eq)]
                pub struct [<RoundKeys $size>]([RoundKey; const { match $size {
                    128 => 11,
                    192 => 13,
                    256 => 15,
                    _ => panic!("unknown key size"),
                }}]);

                impl [<RoundKeys $size>] {
                    pub const fn len(&self) -> usize {
                        self.0.len()
                    }

                    #[cfg(test)]
                    pub fn from_keys(value: [RoundKey; const { match $size {
                        128 => 11,
                        192 => 13,
                        256 => 15,
                        _ => panic!("unknown key size"),
                    }}]) -> Self {
                        Self(value)
                    }
                }


                impl Index<usize> for [<RoundKeys $size>] {
                    type Output = RoundKey;

                    fn index(&self, index: usize) -> &Self::Output {
                        &self.0[index]
                    }
                }
            )+
        }
    };
}

impl_keys!(128);

#[derive(Clone, PartialEq, Eq)]
pub struct RoundKey([u8; 16]);

impl RoundKey {
    pub fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    #[cfg(test)]
    pub fn from_rows(value: [[u8; 4]; 4]) -> Self {
        let mut output = [0u8; 16];

        for i in 0..16 {
            output[i] = value[i % 4][i / 4];
        }

        Self(output)
    }

    pub fn column(&self, index: usize) -> &[u8; 4] {
        assert!(index <= 3, "index needs to be in range 0..=3");
        self.0
            .get((index * 4)..(index * 4 + 4))
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn set_column(&mut self, index: usize, col: [u8; 4]) {
        assert!(index <= 3, "index needs to be in range 0..=3");
        self.0[(index * 4)..(index * 4 + 4)].copy_from_slice(&col)
    }
}

impl fmt::Debug for RoundKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for row in 0..4 {
            let elements: Vec<u8> = (0..4).map(|i| self.0[i * 4 + row]).collect();
            writeln!(
                f,
                "{:02x} {:02x} {:02x} {:02x}",
                elements[0], elements[1], elements[2], elements[3]
            )?;
        }
        Ok(())
    }
}

impl Key128 {
    pub fn expand(self) -> RoundKeys128 {
        let mut rounds: [RoundKey; 11] = [const { RoundKey([0u8; 16]) }; 11];

        // the first round key is the key itself
        rounds[0] = RoundKey(self.0);

        let mut previous_round_key = RoundKey(self.0);

        for i in 1..11 {
            let mut new_round_key = RoundKey([0; 16]);

            new_round_key.set_column(0, {
                let mut column = *previous_round_key.column(3);

                rot_word(&mut column);
                sub_word(&mut column);
                rcon(&mut column, ROUND_CONSTANTS[i - 1]);

                let previous_column = rounds[i - 1].column(0);

                column = gf::add_word(column, *previous_column);
                column
            });

            new_round_key.set_column(1, {
                let mut column = *new_round_key.column(0);
                let previous_column = previous_round_key.column(1);
                column = gf::add_word(column, *previous_column);
                column
            });

            new_round_key.set_column(2, {
                let column = *new_round_key.column(1);
                let previous_column = previous_round_key.column(2);
                gf::add_word(column, *previous_column)
            });

            new_round_key.set_column(3, {
                let column = *new_round_key.column(2);
                let previous_column = previous_round_key.column(3);
                gf::add_word(column, *previous_column)
            });

            previous_round_key = new_round_key.clone();
            rounds[i] = new_round_key;
        }

        RoundKeys128(rounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot_word() {
        let mut word = [0x01, 0x02, 0x03, 0x04];
        rot_word(&mut word);
        assert_eq!(word, [0x02, 0x03, 0x04, 0x01]);
    }

    #[test]
    fn test_sub_word() {
        let mut word = [0x01, 0x02, 0x03, 0x04];
        sub_word(&mut word);
        assert_eq!(word, [0x7c, 0x77, 0x7b, 0xf2]);
    }

    #[test]
    fn test_column() {
        let key = Key128::from_bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        assert_eq!(key.column(0), &[0x2b, 0x7e, 0x15, 0x16]);
        assert_eq!(key.column(3), &[0x09, 0xcf, 0x4f, 0x3c]);
    }

    #[test]
    /// taken from the example in the spec
    fn test_expand_128() {
        let key = Key128::from_bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        let round_keys = key.expand();

        assert_eq!(
            round_keys,
            RoundKeys128::from_keys([
                RoundKey([
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ]),
                RoundKey([
                    0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a,
                    0x6c, 0x76, 0x05,
                ]),
                RoundKey([
                    0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73,
                    0x59, 0xf6, 0x7f,
                ]),
                RoundKey([
                    0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d,
                    0x7a, 0x88, 0x3b,
                ]),
                RoundKey([
                    0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb,
                    0x0b, 0xad, 0x00,
                ]),
                RoundKey([
                    0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11,
                    0xf9, 0x15, 0xbc,
                ]),
                RoundKey([
                    0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca,
                    0x00, 0x93, 0xfd,
                ]),
                RoundKey([
                    0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e,
                    0xa6, 0xdc, 0x4f,
                ]),
                RoundKey([
                    0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f,
                    0x8d, 0x29, 0x2f,
                ]),
                RoundKey([
                    0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57,
                    0x5c, 0x00, 0x6e,
                ]),
                RoundKey([
                    0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6,
                    0x63, 0x0c, 0xa6,
                ])
            ])
        );
    }
}

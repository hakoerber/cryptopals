//! AES standard:
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
//!
//! https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md
//! https://github.com/francisrstokes/AES-C/tree/main/src
//! https://loup-vaillant.fr/articles/crypto-is-not-magic
//! https://de.wikipedia.org/wiki/Advanced_Encryption_Standard
//! https://www.cryptopals.com/sets/1/challenges/7

mod gf {
    //! Operations in the galois field GF(2⁸)
    //!
    //! The Rijndael field uses the following irreducilbe polynomial for multiplication:
    //!
    //! x⁸ + x⁴ + x³ + x + 1
    //!
    //! In binary, this corresponds to 0b1_0001_1011, 0x11b

    pub fn add_word(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
        let mut result = [0; 4];
        result[0] = add(a[0], b[0]);
        result[1] = add(a[1], b[1]);
        result[2] = add(a[2], b[2]);
        result[3] = add(a[3], b[3]);
        result
    }

    /// Addition is defined as addition of the polynomial's coefficients modulo 2.
    ///
    /// This is equivalent to a simple XOR.
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Multiplication is defined as polynomial multiplication modulo the irreducible
    /// polynomial. The modulo operation can be applied to intermediate steps in the
    /// polynomial multiplication.
    ///
    /// The implementation here uses an algorithm derived from "peasants multiplication"
    /// https://en.wikipedia.org/wiki/Ancient_Egyptian_multiplication
    ///
    /// For each non-zero term in `b`, we multiply only that term by `a`. As this is
    /// always a power of two, it can be implemented as a left bit shift.
    pub fn mult(a: u8, b: u8) -> u8 {
        let (mut a, mut b) = (a, b);
        let mut result: u8 = 0;

        // If the LSB is set, we add the polynomial terms of a to the result
        while a != 0 && b != 0 {
            if (b & 1) == 1 {
                result = add(result, a);
            }

            // This divides the polynomial by x and discards the x⁰ term
            b >>= 1;

            // We have to keep track of the MSB (i.e. the term x⁷). If it is non-zero,
            // it needs to be reduced after the right shift (i.e. when it becomes x⁸).
            //
            // Note that we are operating on single bytes here, so the highest bit in0x11b
            // is not considered. As the left shift gets rid of it anyway, this is fine.
            if (a & 0x80) != 0 {
                a = add(a << 1, 0x1b);
            } else {
                a <<= 1;
            }
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_mult() {
            assert_eq!(mult(0, 0), 0);
            assert_eq!(mult(1, 0), 0);
            assert_eq!(mult(0x53, 0xCA), 0x01);
        }
    }
}

mod state {
    use super::{gf, key::RoundKey, SBOX_DECRYPT, SBOX_ENCRYPT};
    use std::{fmt, ops};

    /// A block is two dimensional, column-major order array.
    #[derive(Clone, PartialEq, Eq)]
    pub struct State([u8; 16]);

    impl fmt::Debug for State {
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

    #[derive(Debug, PartialEq, Eq)]
    pub struct Column([u8; 4]);

    impl Column {
        fn mix(&mut self) {
            // matrix multiplication, `a` being the input (i.e. the column):
            // ┌             ┐ ┌    ┐
            // │ 02 03 01 01 │ │ a1 │
            // │ 01 02 03 01 │ │ a2 │
            // │ 01 01 02 03 │ │ a3 │
            // │ 03 01 01 02 │ │ a4 │
            // └             ┘ └    ┘
            //
            // we compute column * matrix
            let mut tmp = [0; 4];

            tmp[0] = gf::mult(0x02, self.0[0]) ^ gf::mult(0x03, self.0[1]) ^ self.0[2] ^ self.0[3];
            tmp[1] = self.0[0] ^ gf::mult(0x02, self.0[1]) ^ gf::mult(0x03, self.0[2]) ^ self.0[3];
            tmp[2] = self.0[0] ^ self.0[1] ^ gf::mult(0x02, self.0[2]) ^ gf::mult(0x03, self.0[3]);
            tmp[3] = gf::mult(0x03, self.0[0]) ^ self.0[1] ^ self.0[2] ^ gf::mult(0x02, self.0[3]);

            self.0[0] = tmp[0];
            self.0[1] = tmp[1];
            self.0[2] = tmp[2];
            self.0[3] = tmp[3];
        }

        fn inv_mix(&mut self) {
            // matrix multiplication, `a` being the input (i.e. the column):
            // ┌             ┐ ┌    ┐
            // │ 0e 0b 0d 09 │ │ a1 │
            // │ 09 0e 0b 0d │ │ a2 │
            // │ 0d 09 0e 0b │ │ a3 │
            // │ 0b 0d 09 0e │ │ a4 │
            // └             ┘ └    ┘
            //
            // we compute column * matrix
            let mut tmp = [0; 4];

            tmp[0] = gf::mult(0x0e, self.0[0])
                ^ gf::mult(0x0b, self.0[1])
                ^ gf::mult(0x0d, self.0[2])
                ^ gf::mult(0x09, self.0[3]);
            tmp[1] = gf::mult(0x09, self.0[0])
                ^ gf::mult(0x0e, self.0[1])
                ^ gf::mult(0x0b, self.0[2])
                ^ gf::mult(0x0d, self.0[3]);
            tmp[2] = gf::mult(0x0d, self.0[0])
                ^ gf::mult(0x09, self.0[1])
                ^ gf::mult(0x0e, self.0[2])
                ^ gf::mult(0x0b, self.0[3]);
            tmp[3] = gf::mult(0x0b, self.0[0])
                ^ gf::mult(0x0d, self.0[1])
                ^ gf::mult(0x09, self.0[2])
                ^ gf::mult(0x0e, self.0[3]);

            self.0[0] = tmp[0];
            self.0[1] = tmp[1];
            self.0[2] = tmp[2];
            self.0[3] = tmp[3];
        }
    }

    impl State {
        pub fn from_bytes(input: [u8; 16]) -> Self {
            Self(input)
        }

        #[cfg(test)]
        pub fn from_rows(input: [[u8; 4]; 4]) -> Self {
            let mut result = [0; 16];
            for c in 0..4 {
                for r in 0..4 {
                    result[c * 4 + r] = input[r][c]
                }
            }
            Self(result)
        }

        pub fn into_array(self) -> [u8; 16] {
            self.0
        }

        fn apply_sbox(&mut self, sbox: [u8; 256]) {
            for i in 0..self.0.len() {
                self.0[i] = sbox[self.0[i] as usize]
            }
        }

        pub fn sub_bytes(&mut self) {
            self.apply_sbox(SBOX_ENCRYPT);
        }

        pub fn inv_sub_bytes(&mut self) {
            self.apply_sbox(SBOX_DECRYPT);
        }

        #[expect(
            clippy::identity_op,
            clippy::erasing_op,
            reason = "to keep the indices visible"
        )]
        pub fn shift_rows(&mut self) {
            // row 1 is unshifted

            // row 2 is shifted left by 1 byte
            let tmp = self.0[4 * 0 + 1];
            self.0[4 * 0 + 1] = self.0[4 * 1 + 1];
            self.0[4 * 1 + 1] = self.0[4 * 2 + 1];
            self.0[4 * 2 + 1] = self.0[4 * 3 + 1];
            self.0[4 * 3 + 1] = tmp;

            // row 2 is shifted left by 2 bytes
            let (tmp1, tmp2) = (self.0[4 * 0 + 2], self.0[4 * 1 + 2]);
            self.0[4 * 0 + 2] = self.0[4 * 2 + 2];
            self.0[4 * 1 + 2] = self.0[4 * 3 + 2];
            self.0[4 * 2 + 2] = tmp1;
            self.0[4 * 3 + 2] = tmp2;

            // row 3 is shifted left by 3 bytes, or right by 1 byte (which needs fewer tmps)
            let tmp = self.0[4 * 3 + 3];
            self.0[4 * 3 + 3] = self.0[4 * 2 + 3];
            self.0[4 * 2 + 3] = self.0[4 * 1 + 3];
            self.0[4 * 1 + 3] = self.0[4 * 0 + 3];
            self.0[4 * 0 + 3] = tmp;
        }

        #[expect(
            clippy::identity_op,
            clippy::erasing_op,
            reason = "to keep the indices visible"
        )]
        pub fn inv_shift_rows(&mut self) {
            // row 1 is unshifted

            // row 2 is shifted right by 1 byte
            let tmp = self.0[4 * 3 + 1];
            self.0[4 * 3 + 1] = self.0[4 * 2 + 1];
            self.0[4 * 2 + 1] = self.0[4 * 1 + 1];
            self.0[4 * 1 + 1] = self.0[4 * 0 + 1];
            self.0[4 * 0 + 1] = tmp;

            // row 2 is shifted left by 2 bytes
            let (tmp1, tmp2) = (self.0[4 * 0 + 2], self.0[4 * 1 + 2]);
            self.0[4 * 0 + 2] = self.0[4 * 2 + 2];
            self.0[4 * 1 + 2] = self.0[4 * 3 + 2];
            self.0[4 * 2 + 2] = tmp1;
            self.0[4 * 3 + 2] = tmp2;

            // row 3 is shifted right by 3 bytes, or left by 1 byte (which needs fewer tmps)
            let tmp = self.0[4 * 0 + 3];
            self.0[4 * 0 + 3] = self.0[4 * 1 + 3];
            self.0[4 * 1 + 3] = self.0[4 * 2 + 3];
            self.0[4 * 2 + 3] = self.0[4 * 3 + 3];
            self.0[4 * 3 + 3] = tmp;
        }

        pub fn mix_columns(&mut self) {
            for i in 0..4 {
                let mut column = self.column(i);
                column.mix();
                self.set_column(i, column);
            }
        }

        pub fn inv_mix_columns(&mut self) {
            for i in 0..4 {
                let mut column = self.column(i);
                column.inv_mix();
                self.set_column(i, column);
            }
        }

        /// Note that each **word** (i.e. 4 bytes) of the round key are combined with
        /// each **column** of the key
        ///
        /// no inv_ needed, it's its own inverse
        pub fn add_round_key(&mut self, round_key: &RoundKey) {
            for i in 0..4 {
                let mut column = self.column(i);
                let key_word: &[u8; 4] = round_key.column(i);
                for (j, key_column) in key_word.iter().enumerate().take(4) {
                    column.0[j] ^= key_column
                }
                self.set_column(i, column)
            }
        }

        fn column(&self, index: usize) -> Column {
            if index > 3 {
                panic!("block only has 4 columns")
            }
            Column(self.0[(index * 4)..(index * 4 + 4)].try_into().unwrap())
        }

        fn set_column(&mut self, index: usize, column: Column) {
            if index > 3 {
                panic!("block only has 4 columns")
            }
            for i in 0..4 {
                self.0[index * 4 + i] = column.0[i]
            }
        }
    }

    impl ops::Index<(usize, usize)> for State {
        type Output = u8;

        fn index(&self, index: (usize, usize)) -> &Self::Output {
            let (row, col) = index;
            &self.0[row + 4 * col]
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::aes::key::RoundKey;

        use super::*;

        fn state_indexed() -> State {
            let input = (0..16).into_iter().collect::<Vec<u8>>().try_into().unwrap();
            State::from_bytes(input)
        }

        #[test]
        fn test_from_array() {
            let state = state_indexed();

            assert_eq!(state[(0, 0)], 0);
            assert_eq!(state[(1, 0)], 1);
            assert_eq!(state[(2, 0)], 2);
            assert_eq!(state[(3, 0)], 3);
            assert_eq!(state[(0, 1)], 4);
            assert_eq!(state[(1, 1)], 5);
            assert_eq!(state[(2, 1)], 6);
            assert_eq!(state[(3, 1)], 7);
            assert_eq!(state[(0, 2)], 8);
            assert_eq!(state[(1, 2)], 9);
            assert_eq!(state[(2, 2)], 10);
            assert_eq!(state[(3, 2)], 11);
            assert_eq!(state[(0, 3)], 12);
            assert_eq!(state[(1, 3)], 13);
            assert_eq!(state[(2, 3)], 14);
            assert_eq!(state[(3, 3)], 15);
        }

        #[test]
        fn test_to_array() {
            let state = state_indexed();
            let output = state.into_array();

            assert_eq!(
                output,
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            );
        }

        #[test]
        fn test_column_index() {
            let state = state_indexed();

            assert_eq!(state.column(0), Column([0, 1, 2, 3]));
            assert_eq!(state.column(1), Column([4, 5, 6, 7]));
            assert_eq!(state.column(2), Column([8, 9, 10, 11]));
            assert_eq!(state.column(3), Column([12, 13, 14, 15]));
        }

        #[test]
        fn test_sub_bytes_encrypt() {
            let mut state = State::from_rows([
                [0x19, 0xa0, 0x9a, 0xe9],
                [0x3d, 0xf4, 0xc6, 0xf8],
                [0xe3, 0xe2, 0x8d, 0x48],
                [0xbe, 0x2b, 0x2a, 0x08],
            ]);

            state.sub_bytes();

            assert_eq!(
                state,
                State::from_rows([
                    [0xd4, 0xe0, 0xb8, 0x1e],
                    [0x27, 0xbf, 0xb4, 0x41],
                    [0x11, 0x98, 0x5d, 0x52],
                    [0xae, 0xf1, 0xe5, 0x30],
                ])
            );
        }

        #[test]
        fn test_shift_rows() {
            let mut state = State::from_rows([
                [0x74, 0xc5, 0xdf, 0x3c],
                [0x6c, 0x1e, 0x93, 0x62],
                [0xe1, 0xdd, 0x79, 0xb0],
                [0x09, 0x3b, 0xc7, 0xe7],
            ]);

            state.shift_rows();

            assert_eq!(
                state,
                State::from_rows([
                    [0x74, 0xc5, 0xdf, 0x3c],
                    [0x1e, 0x93, 0x62, 0x6c],
                    [0x79, 0xb0, 0xe1, 0xdd],
                    [0xe7, 0x09, 0x3b, 0xc7],
                ])
            );
        }

        #[test]
        fn test_inv_shift_rows() {
            let mut state = State::from_rows([
                [0x74, 0xc5, 0xdf, 0x3c],
                [0x6c, 0x1e, 0x93, 0x62],
                [0xe1, 0xdd, 0x79, 0xb0],
                [0x09, 0x3b, 0xc7, 0xe7],
            ]);

            state.inv_shift_rows();

            assert_eq!(
                state,
                State::from_rows([
                    [0x74, 0xc5, 0xdf, 0x3c],
                    [0x62, 0x6c, 0x1e, 0x93],
                    [0x79, 0xb0, 0xe1, 0xdd],
                    [0x3b, 0xc7, 0xe7, 0x09],
                ])
            );
        }

        #[test]
        fn test_mix_column() {
            // https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
            for (before, after) in [
                ([0xdb, 0x13, 0x53, 0x45], [0x8e, 0x4d, 0xa1, 0xbc]),
                ([0xf2, 0x0a, 0x22, 0x5c], [0x9f, 0xdc, 0x58, 0x9d]),
                ([0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01]),
                ([0xc6, 0xc6, 0xc6, 0xc6], [0xc6, 0xc6, 0xc6, 0xc6]),
                ([0xd4, 0xd4, 0xd4, 0xd5], [0xd5, 0xd5, 0xd7, 0xd6]),
                ([0x2d, 0x26, 0x31, 0x4c], [0x4d, 0x7e, 0xbd, 0xf8]),
            ] {
                let mut column = Column(before);
                column.mix();
                assert_eq!(column, Column(after));
            }
        }

        #[test]
        fn text_mix_columns() {
            let mut state = State::from_rows([
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5],
            ]);

            state.mix_columns();

            assert_eq!(
                state,
                State::from_rows([
                    [0x04, 0xe0, 0x48, 0x28],
                    [0x66, 0xcb, 0xf8, 0x06],
                    [0x81, 0x19, 0xd3, 0x26],
                    [0xe5, 0x9a, 0x7a, 0x4c],
                ])
            );
        }

        #[test]
        fn test_add_round_key() {
            let mut state = State::from_rows([
                [0x04, 0xe0, 0x48, 0x28],
                [0x66, 0xcb, 0xf8, 0x06],
                [0x81, 0x19, 0xd3, 0x26],
                [0xe5, 0x9a, 0x7a, 0x4c],
            ]);

            let key = RoundKey::from_rows([
                [0xa0, 0x88, 0x23, 0x2a],
                [0xfa, 0x54, 0xa3, 0x6c],
                [0xfe, 0x2c, 0x39, 0x76],
                [0x17, 0xb1, 0x39, 0x05],
            ]);

            state.add_round_key(&key);

            assert_eq!(
                state,
                State::from_rows([
                    [0xa4, 0x68, 0x6b, 0x02],
                    [0x9c, 0x9f, 0x5b, 0x6a],
                    [0x7f, 0x35, 0xea, 0x50],
                    [0xf2, 0x2b, 0x43, 0x49],
                ])
            );
        }
    }
}

mod key {
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
                        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c,
                    ]),
                    RoundKey([
                        0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39,
                        0x2a, 0x6c, 0x76, 0x05,
                    ]),
                    RoundKey([
                        0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a,
                        0x73, 0x59, 0xf6, 0x7f,
                    ]),
                    RoundKey([
                        0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44,
                        0x6d, 0x7a, 0x88, 0x3b,
                    ]),
                    RoundKey([
                        0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b,
                        0xdb, 0x0b, 0xad, 0x00,
                    ]),
                    RoundKey([
                        0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc,
                        0x11, 0xf9, 0x15, 0xbc,
                    ]),
                    RoundKey([
                        0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41,
                        0xca, 0x00, 0x93, 0xfd,
                    ]),
                    RoundKey([
                        0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2,
                        0x4e, 0xa6, 0xdc, 0x4f,
                    ]),
                    RoundKey([
                        0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60,
                        0x7f, 0x8d, 0x29, 0x2f,
                    ]),
                    RoundKey([
                        0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41,
                        0x57, 0x5c, 0x00, 0x6e,
                    ]),
                    RoundKey([
                        0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8,
                        0xb6, 0x63, 0x0c, 0xa6,
                    ])
                ])
            );
        }
    }
}

pub use key::Key128;

use state::State;

const SBOX_ENCRYPT: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const SBOX_DECRYPT: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn cipher(input: [u8; 16], round_keys: &key::RoundKeys128) -> [u8; 16] {
    let mut state = State::from_bytes(input);

    state.add_round_key(&round_keys[0]);

    for i in 1..(round_keys.len() - 1) {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_keys[i]);
    }

    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_keys[round_keys.len() - 1]);

    state.into_array()
}

pub fn inv_cipher(input: [u8; 16], round_keys: &key::RoundKeys128) -> [u8; 16] {
    let mut state = State::from_bytes(input);

    state.add_round_key(&round_keys[round_keys.len() - 1]);

    for i in (1..(round_keys.len() - 1)).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_keys[i]);
        state.inv_mix_columns();
    }

    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_keys[0]);

    state.into_array()
}

pub fn decrypt_ecb(ciphertext: &[u8], key: Key128) -> Vec<u8> {
    let mut output = Vec::with_capacity(ciphertext.len());

    let round_keys = key.expand();

    for chunk in ciphertext.chunks(16) {
        let chunk = chunk
            .try_into()
            .expect("input length needs to be a multiple of 16");
        let decrypted = inv_cipher(chunk, &round_keys);
        output.extend_from_slice(&decrypted);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox() {
        let mut block = State::from_rows([
            [0x74, 0xc5, 0xdf, 0x3c],
            [0x6c, 0x1e, 0x93, 0x62],
            [0xe1, 0xdd, 0x79, 0xb0],
            [0x09, 0x3b, 0xc7, 0xe7],
        ]);

        let expected = State::from_rows([
            [0x92, 0xa6, 0x9e, 0xeb],
            [0x50, 0x72, 0xdc, 0xaa],
            [0xf8, 0xc1, 0xb6, 0xe7],
            [0x01, 0xe2, 0xc6, 0x94],
        ]);

        block.sub_bytes();

        assert_eq!(block, expected);
    }

    #[test]
    fn test_shift_bytes() {
        let mut block = State::from_rows([
            [0x74, 0xc5, 0xdf, 0x3c],
            [0x6c, 0x1e, 0x93, 0x62],
            [0xe1, 0xdd, 0x79, 0xb0],
            [0x09, 0x3b, 0xc7, 0xe7],
        ]);

        let expected = State::from_rows([
            [0x74, 0xc5, 0xdf, 0x3c],
            [0x1e, 0x93, 0x62, 0x6c],
            [0x79, 0xb0, 0xe1, 0xdd],
            [0xe7, 0x09, 0x3b, 0xc7],
        ]);

        block.shift_rows();

        assert_eq!(block, expected);
    }

    #[test]
    /// taken from the example in the spec
    fn test_encrypt_block_from_spec() {
        let cleartext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let key = key::Key128::from_bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);

        let expected_ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        assert_eq!(cipher(cleartext, &key.expand()), expected_ciphertext);
    }

    #[test]
    fn test_encrypt_block() {
        let cleartext: [u8; 16] = "SUPER TOP SECRET".as_bytes().try_into().unwrap();
        let key = key::Key128::from_bytes("YELLOW SUBMARINE".as_bytes().try_into().unwrap());
        let expected_ciphertext: [u8; 16] = [
            0x4a, 0x5b, 0xe2, 0x51, 0x8e, 0x40, 0xa3, 0x7b, 0xdb, 0x4e, 0xb5, 0x2e, 0x83, 0xc1,
            0x48, 0x05,
        ];

        assert_eq!(cipher(cleartext, &key.expand()), expected_ciphertext);
    }

    #[test]
    fn test_decrypt_block() {
        let cleartext: [u8; 16] = "SUPER TOP SECRET".as_bytes().try_into().unwrap();
        let ciphertext: [u8; 16] = [
            0x4a, 0x5b, 0xe2, 0x51, 0x8e, 0x40, 0xa3, 0x7b, 0xdb, 0x4e, 0xb5, 0x2e, 0x83, 0xc1,
            0x48, 0x05,
        ];
        let key = key::Key128::from_bytes("YELLOW SUBMARINE".as_bytes().try_into().unwrap());

        assert_eq!(inv_cipher(ciphertext, &key.expand()), cleartext);
    }
}

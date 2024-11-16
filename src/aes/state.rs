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

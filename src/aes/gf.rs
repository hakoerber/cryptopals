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

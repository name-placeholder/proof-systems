use ark_ff::{biginteger::BigInteger256 as BigInteger, FftParameters, Fp256Parameters, Fp256};

pub type Fp = Fp256<FpParameters>;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct FpParameters;

impl Fp256Parameters for FpParameters {}

#[rustfmt::skip]
impl FftParameters for FpParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 32;

    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = {
        const TWO_ADIC_ROOT_OF_UNITY: Fp = ark_ff::field_new!(Fp, "19814229590243028906643993866117402072516588566294623396325693409366934201135");
        TWO_ADIC_ROOT_OF_UNITY.0
    };
}

#[cfg(not(any(target_family = "wasm", feature = "32x9")))]
pub mod native {
    use super::*;

    impl ark_ff::FpParameters for FpParameters {
        // 28948022309329048855892746252171976963363056481941560715954676764349967630337
        const MODULUS: BigInteger = BigInteger::new([
            0x992d30ed00000001,
            0x224698fc094cf91b,
            0x0,
            0x4000000000000000,
        ]);
        const R: BigInteger = BigInteger::new([
            0x34786d38fffffffd,
            0x992c350be41914ad,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ]);
        const R2: BigInteger = BigInteger::new([
            0x8c78ecb30000000f,
            0xd7d30dbd8b0de0e7,
            0x7797a99bc3c95d18,
            0x96d41af7b9cb714,
        ]);
        const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
            0xcc96987680000000,
            0x11234c7e04a67c8d,
            0x0,
            0x2000000000000000,
        ]);
        // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
        const T: BigInteger = BigInteger::new([0x94cf91b992d30ed, 0x224698fc, 0x0, 0x40000000]);
        const T_MINUS_ONE_DIV_TWO: BigInteger =
            BigInteger::new([0x4a67c8dcc969876, 0x11234c7e, 0x0, 0x20000000]);
        // GENERATOR = 5
        const GENERATOR: BigInteger = BigInteger::new([
            0xa1a55e68ffffffed,
            0x74c2a54b4f4982f3,
            0xfffffffffffffffd,
            0x3fffffffffffffff,
        ]);
        const MODULUS_BITS: u32 = 255;
        const CAPACITY: u32 = Self::MODULUS_BITS - 1;
        const REPR_SHAVE_BITS: u32 = 1;
        // -(MODULUS^{-1} mod 2^64) mod 2^64
        const INV: u64 = 11037532056220336127;
    }
}

#[cfg(any(target_family = "wasm", feature = "32x9"))]
pub mod x32x9 {
    use super::*;

    #[rustfmt::skip]
    impl ark_ff::FpParameters for FpParameters {
        // 28948022309329048855892746252171976963363056481941560715954676764349967630337
        const MODULUS: BigInteger = BigInteger::new([
            0x1, 0x9698768, 0x133e46e6, 0xd31f812, 0x224, 0x0, 0x0, 0x0, 0x400000,
        ]);
        const R: BigInteger = BigInteger::new([
            0x1fffff81, 0x14a5d367, 0x141ad3c0, 0x1435eec5, 0x1ffeefef, 0x1fffffff, 0x1fffffff,
            0x1fffffff, 0x3fffff,
        ]);
        const R2: BigInteger = BigInteger::new([
            0x3b6a, 0x19c10910, 0x1a6a0188, 0x12a4fd88, 0x634b36d, 0x178792ba, 0x7797a99, 0x1dce5b8a,
            0x3506bd,
        ]);
        // TODO
        const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
            0x0, 0x4b4c3b4, 0x99f2373, 0x698fc09, 0x112, 0x0, 0x0, 0x0, 0x200000,
        ]);
        // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
        const T: BigInteger = BigInteger::new([
            0x192d30ed, 0xa67c8dc, 0x11a63f02, 0x44, 0x0, 0x0, 0x0, 0x80000, 0x0,
        ]);
        const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger::new([
            0xc969876, 0x533e46e, 0x8d31f81, 0x22, 0x0, 0x0, 0x0, 0x40000, 0x0,
        ]);
        // GENERATOR = 5
        const GENERATOR: BigInteger = {
            const FIVE: Fp = ark_ff::field_new!(Fp, "5");
            FIVE.0
        };
        const MODULUS_BITS: u32 = 255;
        const CAPACITY: u32 = Self::MODULUS_BITS - 1;
        const REPR_SHAVE_BITS: u32 = 1;
        // -(MODULUS^{-1} mod 2^64) mod 2^64
        const INV: u64 = 0x1fffffff;
    }
}

use ark_ff::{biginteger::BigInteger256 as BigInteger, FftParameters, Fp256Parameters, NewFp256};

pub type Fp = NewFp256<FpParameters>;

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

#[rustfmt::skip]
impl ark_ff::FpParameters for FpParameters {
    // 28948022309329048855892746252171976963363056481941560715954676764349967630337
    const MODULUS: BigInteger = BigInteger([
        0x1, 0x9698768, 0x133e46e6, 0xd31f812, 0x224, 0x0, 0x0, 0x0, 0x400000,
    ]);

    const R: BigInteger = BigInteger([
        0x1fffff81, 0x14a5d367, 0x141ad3c0, 0x1435eec5, 0x1ffeefef, 0x1fffffff, 0x1fffffff,
        0x1fffffff, 0x3fffff,
    ]);

    const R2: BigInteger = BigInteger([
        0x3b6a, 0x19c10910, 0x1a6a0188, 0x12a4fd88, 0x634b36d, 0x178792ba, 0x7797a99, 0x1dce5b8a,
        0x3506bd,
    ]);

    // TODO
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x0, 0x4b4c3b4, 0x99f2373, 0x698fc09, 0x112, 0x0, 0x0, 0x0, 0x200000,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
    const T: BigInteger = BigInteger([
        0x192d30ed, 0xa67c8dc, 0x11a63f02, 0x44, 0x0, 0x0, 0x0, 0x80000, 0x0,
    ]);

    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
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

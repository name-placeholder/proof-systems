use ark_ff::{biginteger::BigInteger256 as BigInteger, FftParameters, Fp256Parameters, NewFp256};

pub type Fq = NewFp256<FqParameters>;


#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct FqParameters;

impl Fp256Parameters for FqParameters {}

#[rustfmt::skip]
impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 32;

    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = {
        const TWO_ADIC_ROOT_OF_UNITY: Fq = ark_ff::field_new!(Fq, "20761624379169977859705911634190121761503565370703356079647768903521299517535");
        TWO_ADIC_ROOT_OF_UNITY.0
    };
}

#[rustfmt::skip]
impl ark_ff::FpParameters for FqParameters {
    // 28948022309329048855892746252171976963363056481941560715954676764349967630337
    const MODULUS: BigInteger = BigInteger([
        0x1, 0x2375908, 0x52a3763, 0xd31f813, 0x224, 0x0, 0x0, 0x0, 0x400000,
    ]);

    const R: BigInteger = BigInteger([
        0x1fffff81, 0x68ad507, 0x100e85da, 0x1435ee7e, 0x1ffeefef, 0x1fffffff, 0x1fffffff,
        0x1fffffff, 0x3fffff,
    ]);

    const R2: BigInteger = BigInteger([
        0x3b6a, 0x2b1b550, 0x1027888a, 0x1ea4ed96, 0x418ad7a, 0x999eb, 0x17fae231,
        0x1e67ed54, 0x3506bd,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x0, 0x111bac84, 0x12951bb1, 0x698fc09, 0x112, 0x0, 0x0, 0x0, 0x200000,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
    const T: BigInteger = BigInteger([
        0xc46eb21, 0xca546ec, 0x11a63f02, 0x44, 0x0, 0x0, 0x0, 0x80000, 0x0,
    ]);

    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x6237590, 0x652a376, 0x8d31f81, 0x22, 0x0, 0x0, 0x0, 0x40000, 0x0,
    ]);

    // GENERATOR = 5
    const GENERATOR: BigInteger = {
        const FIVE: Fq = ark_ff::field_new!(Fq, "5");
        FIVE.0
    };

    const MODULUS_BITS: u32 = 255;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 1;

    // -(MODULUS^{-1} mod 2^64) mod 2^64
    const INV: u64 = 0x1fffffff;
}

use std::sync::atomic::AtomicUsize;

use ark_ec::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    AffineCurve, ProjectiveCurve, SWModelParameters as Parameter,
};
use ark_ff::{BigInteger, FpParameters};
use ark_ff::{BigInteger256, Field, One, PrimeField, Zero};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::commitment::CommitmentCurve;

pub static MSM_DURATION: AtomicUsize = AtomicUsize::new(0);
pub static MSM_INDEX: AtomicUsize = AtomicUsize::new(0);

pub fn call_msm<G: CommitmentCurve>(
    points: &[G],
    scalars: &[<<G as AffineCurve>::ScalarField as PrimeField>::BigInt],
) -> G::Projective {
    // let now = std::time::Instant::now();

    let res = if scalars.iter().any(|s| s.is_zero()) {
        // Unfortunatly, in many cases `call_msm` is called with many zeros in `scalars`
        // When that occur, we can't use the batched additions, because digits are not
        // evenly distributed in each bucket. That would be slower than
        // non-batched msm
        ark_ec::msm::VariableBaseMSM::multi_scalar_mul(points, scalars)
    } else {
        // In the few cases when there is no zero in `scalars`, our MSM is about 30% faster
        // than `ark_ec::msm::VariableBaseMSM::multi_scalar_mul`
        call_msm_impl(points, scalars)
    };

    // let elapsed = now.elapsed();
    // MSM_DURATION.fetch_add(elapsed.as_millis().try_into().unwrap(), std::sync::atomic::Ordering::Relaxed);

    res
}

// /// Use to compare window sizes
// pub fn call_msm2<G: CommitmentCurve>(
//     points: &[G],
//     scalars: &[<<G as AffineCurve>::ScalarField as PrimeField>::BigInt],
// ) -> G::Projective {
//     let mut map = HashMap::new();

//     let size = std::cmp::min(points.len(), scalars.len());

//     // let c = if size <= 8194 { 8 } else { 13 };

//     for c in 5..15 {
//         // dbg!(c);
//         let now = std::time::Instant::now();
//         let _res = call_msm_impl(&points[..size], &scalars[..size], c);
//         let elapsed = now.elapsed();
//         map.insert(c, elapsed);
//     }

//     let now = std::time::Instant::now();
//     let res = ark_ec::msm::VariableBaseMSM::multi_scalar_mul(&points[..size], &scalars[..size]);
//     let ark_elapsed = now.elapsed();

//     let mut best_vec = map.iter().collect::<Vec<_>>();
//     best_vec.sort_by_key(|(_c, dur)| *dur);

//     // dbg!(&best_vec);
//     let best = best_vec.first().unwrap();
//     // assert!(best.1 < best_vec.last().unwrap().1);

//     use ark_ff::BigInteger;
//     let n_zeros = scalars.iter().filter(|s| s.is_zero()).count();

//     // let best = if

//     // MSM_DURATION.fetch_add(best.1.as_millis().try_into().unwrap(), std::sync::atomic::Ordering::Relaxed);
//     // MSM_DURATION.fetch_add(elapsed.as_millis().try_into().unwrap(), std::sync::atomic::Ordering::Relaxed);
//     let index = MSM_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

//     // if ark_elapsed < best.1 {

//     let mut s = "";
//     if best.1 < &ark_elapsed {
//         s = "XXX";
//     }

//     eprintln!(
//         "[{:?}] npoints:{:?} nzeros:{:?} ark_elapsed:{:?} best:{:?} {}",
//         index,
//         points.len(),
//         n_zeros,
//         ark_elapsed,
//         &best_vec[..2],
//         s
//     );
//     // } else {

//     // }
//     // eprintln!("[{:?}] npoints:{:?} nzeros:{:?} elapsed:{:?}", index, points.len(), n_zeros, elapsed);

//     // if points.len() == 16384 {
//     //     std::process::exit(0);
//     // }

//     res
// }

pub fn call_msm_impl<G: CommitmentCurve>(
    points: &[G],
    scalars: &[<<G as AffineCurve>::ScalarField as PrimeField>::BigInt],
) -> G::Projective {
    use std::any::TypeId;

    assert_eq!(TypeId::of::<G>(), TypeId::of::<GroupAffine::<G::Params>>());
    assert_eq!(
        TypeId::of::<G::Projective>(),
        TypeId::of::<GroupProjective::<G::Params>>()
    );
    assert_eq!(
        TypeId::of::<<<G as AffineCurve>::ScalarField as PrimeField>::BigInt>(),
        TypeId::of::<BigInteger256>()
    );

    // Safety: We're reinterpreting generic types to their concret types
    // proof-systems contains too much useless generic types
    // It's safe because we just asserted they are the same types
    let result = my_msm::<G::Params>(unsafe { std::mem::transmute(points) }, unsafe {
        std::mem::transmute(scalars)
    });
    unsafe { *(&result as *const _ as *const G::Projective) }
}

struct Batch<'a, P: Parameter> {
    buckets: Vec<GroupAffine<P>>,
    /// (index in `buckets`, is_negative, group)
    in_batch: Vec<(usize, bool, &'a GroupAffine<P>)>,
    in_batch_busy_buckets: Vec<bool>,
    inverse_state: P::BaseField,
    inverses: Vec<P::BaseField>,
    /// (index in `buckets`, is_negative, group)
    pendings: Vec<(usize, bool, &'a GroupAffine<P>)>,
}

const N_BATCH: usize = 4096;
const N_COLLISION: usize = 512;

impl<'a, P: Parameter> Batch<'a, P> {
    pub fn with_capacity(capacity: usize) -> Self {
        let zero = GroupAffine::zero();
        Self {
            buckets: vec![zero; capacity],
            in_batch: Vec::with_capacity(N_BATCH),
            in_batch_busy_buckets: vec![false; capacity],
            inverse_state: P::BaseField::one(),
            inverses: vec![P::BaseField::one(); N_BATCH],
            pendings: Vec::with_capacity(N_BATCH),
        }
    }

    fn add_in_bucket(&mut self, bucket: usize, is_negative: bool, g: &'a GroupAffine<P>) {
        if self.in_batch_busy_buckets[bucket] {
            self.pendings.push((bucket, is_negative, g));
        } else {
            self.in_batch_busy_buckets[bucket] = true;
            self.in_batch.push((bucket, is_negative, g));
        }
    }

    // Thanks to
    // https://github.com/snarkify/arkmsm/blob/f60cffa905762911a77800a77d524cf7279b63d5/src/batch_adder.rs#L125-L201
    fn accumulate(&mut self) {
        use std::ops::Neg;

        self.inverse_state = P::BaseField::one();

        for (in_batch_index, (bucket_index, is_neg, point)) in
            self.in_batch.iter().copied().enumerate()
        {
            let bucket = &mut self.buckets[bucket_index];
            let mut point = *point;
            if is_neg {
                point = point.neg();
            }
            if bucket.is_zero() | point.is_zero() {
                continue;
            }
            let mut diff_x = point.x - bucket.x;
            if diff_x.is_zero() {
                let diff_y = point.y - bucket.y;
                if !diff_y.is_zero() {
                    continue;
                }
                diff_x = point.y + point.y;
            }
            if self.inverse_state.is_zero() {
                self.inverses[in_batch_index].set_one();
                self.inverse_state = diff_x;
            } else {
                self.inverses[in_batch_index] = self.inverse_state;
                self.inverse_state *= diff_x
            }
        }

        self.inverse_state = self.inverse_state.inverse().unwrap();

        for (in_batch_index, (bucket_index, is_neg, point)) in
            self.in_batch.iter().copied().enumerate().rev()
        {
            let bucket = &mut self.buckets[bucket_index];
            let mut point = *point;
            if is_neg {
                point = point.neg();
            }
            if bucket.is_zero() | point.is_zero() {
                if !point.is_zero() {
                    *bucket = point;
                }
                continue;
            }
            let mut inverse = self.inverses[in_batch_index];
            inverse *= self.inverse_state;
            let mut diff_x = point.x - bucket.x;
            let mut diff_y = point.y - bucket.y;
            if diff_x.is_zero() {
                if !diff_y.is_zero() {
                    bucket.set_zero();
                    continue;
                }
                diff_y = point.x.square();
                diff_y = diff_y + diff_y + diff_y;
                diff_x = point.y.double();
            }
            self.inverse_state *= diff_x;
            let s = diff_y * inverse;
            let ss = s * s;
            bucket.x = ss - point.x - bucket.x;
            diff_x = point.x - bucket.x;
            bucket.y = s * diff_x;
            bucket.y -= point.y;
        }

        self.in_batch.clear();
        self.in_batch_busy_buckets
            .iter_mut()
            .for_each(|b| *b = false);

        self.pendings.retain(|(bucket, is_neg, g)| {
            if self.in_batch_busy_buckets[*bucket] {
                return true;
            }
            self.in_batch_busy_buckets[*bucket] = true;
            self.in_batch.push((*bucket, *is_neg, g));
            false
        });
    }
}

#[derive(Copy, Clone)]
pub struct Digits {
    digits: u32,
}

pub fn my_msm<P: Parameter>(
    bases: &[GroupAffine<P>],
    scalars: &[BigInteger256],
) -> GroupProjective<P> {
    let size = std::cmp::min(bases.len(), scalars.len());
    let scalars = &scalars[..size];
    let bases = &bases[..size];

    let c = match size {
        ..=18 => 6,
        ..=8184 => 8,
        _ => 13,
    };

    let zero = GroupProjective::zero();
    let num_bits =
        <<GroupAffine<P> as AffineCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

    let max = 1 << c;
    let max_half = max >> 1;

    let digits = scalars
        .par_iter()
        .map(|scalar| {
            if scalar.is_zero() {
                return None;
            }
            let mut scalar = *scalar;
            let mut carry = 0;
            Some(
                window_starts
                    .iter()
                    .map(|_win_start| {
                        let mut digits = scalar.to_64x4()[0] % (1 << c);
                        digits += carry;
                        if digits > max_half {
                            digits = max - digits;
                            carry = 1;
                        } else {
                            carry = 0;
                        }
                        let digits = Digits {
                            digits: digits as u32 | ((carry as u32) << 31),
                        };
                        scalar.divn(c as u32);
                        digits
                    })
                    .collect::<smallvec::SmallVec<_, 21>>(),
            )
        })
        .collect::<Vec<_>>();

    let sum_per_window: Vec<_> = window_starts
        .par_iter()
        .copied()
        .enumerate()
        .map(|(window_index, _)| {
            let mut batch = Batch::with_capacity(1 << (c - 1));

            digits.iter().zip(bases).for_each(|(scalar, base)| {
                let Some(scalar) = scalar else {
                    return;
                };
                let Digits { digits } = scalar[window_index];
                let is_neg = (digits >> 31) != 0;
                let digits = ((digits as u32) & ((-1i32 as u32) >> 1)) as usize;
                let Some(digits) = digits.checked_sub(1) else {
                    return;
                };
                batch.add_in_bucket(digits, is_neg, base);
                if batch.in_batch.len() >= N_BATCH || batch.pendings.len() >= N_COLLISION {
                    batch.accumulate();
                }
            });

            while !batch.in_batch.is_empty() || !batch.pendings.is_empty() {
                batch.accumulate();
            }

            // eprintln!(
            //     "total alloc: {:?} accum: {:?} nzeros: {:?} nis_neg:{:?} in_batch_cap: {:?} pendings_cap: {:?}",
            //     elapsed_alloc, now.elapsed(), nzeros, nis_neg, batch.in_batch.capacity(), batch.pendings.capacity(),
            // );

            let mut running_sum = zero;
            batch
                .buckets
                .iter()
                .rev()
                .map(|b| {
                    running_sum.add_assign_mixed(b);
                    running_sum
                })
                .sum()
        })
        .collect();

    let lowest = *sum_per_window.first().unwrap();

    lowest
        + &sum_per_window[1..]
            .iter()
            .rev()
            .fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

pub mod chunked;
mod combine;
pub mod commitment;
pub mod error;
pub mod evaluation_proof;
pub mod msm;
pub mod pairing_proof;
pub mod srs;

// #[cfg(test)]
// mod tests;

pub use commitment::PolyComm;

use crate::commitment::{BatchEvaluationProof, BlindedCommitment, CommitmentCurve};
use crate::error::CommitmentError;
use crate::evaluation_proof::DensePolynomialOrEvaluations;
use ark_ec::AffineCurve;
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use mina_poseidon::FqSponge;
use rand_core::{CryptoRng, RngCore};

pub trait SRS<G: CommitmentCurve> {
    /// The maximum polynomial degree that can be committed to
    fn max_poly_size(&self) -> usize;

    /// Retrieve the precomputed Lagrange basis for the given domain size
    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>>;

    /// Get the group element used for blinding commitments
    fn blinding_commitment(&self) -> G;

    /// Commits a polynomial, potentially splitting the result in multiple commitments.
    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;

    /// Same as [SRS::mask] except that you can pass the blinders manually.
    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> Result<BlindedCommitment<G>, CommitmentError>;

    /// Turns a non-hiding polynomial commitment into a hidding polynomial commitment. Transforms each given `<a, G>` into `(<a, G> + wH, w)` with a random `w` per commitment.
    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        let blinders = comm.map(|_| G::ScalarField::rand(rng));
        self.mask_custom(comm, &blinders).unwrap()
    }

    /// This function commits a polynomial using the SRS' basis of size `n`.
    /// - `plnm`: polynomial to commit to with max size of sections
    /// - `num_chunks`: the number of commitments to be included in the output polynomial commitment
    /// The function returns an unbounded commitment vector
    /// (which splits the commitment into several commitments of size at most `n`).
    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
    ) -> PolyComm<G>;

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G>;

    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G>;
}

#[allow(type_alias_bounds)]
/// Vector of triples (polynomial itself, degree bound, omegas).
type PolynomialsToCombine<'a, G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>> = &'a [(
    DensePolynomialOrEvaluations<'a, G::ScalarField, D>,
    PolyComm<G::ScalarField>,
)];

pub trait OpenProof<G: CommitmentCurve>: Sized {
    type SRS: SRS<G>;

    #[allow(clippy::too_many_arguments)]
    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineCurve>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>, // vector of polynomial with optional degree bound and commitment randomness
        elm: &[<G as AffineCurve>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineCurve>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineCurve>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                 // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineCurve>::BaseField, G, <G as AffineCurve>::ScalarField>,
        RNG: RngCore + CryptoRng;

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng;
}

// #[cfg(test)]
// mod tests {
//     use std::sync::{atomic::AtomicUsize, Mutex, RwLock};

//     use ark_ec::{short_weierstrass_jacobian::{GroupAffine, GroupProjective}, AffineCurve, ProjectiveCurve};
//     use ark_ff::{BigInteger256, Field, PrimeField, UniformRand};
//     use mina_curves::pasta::{Fp, Pallas, PallasParameters};
//     use o1_utils::foreign_field::FieldArrayBigUintHelpers;
//     use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

//     fn get_rng() -> rand::rngs::StdRng {
//         <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0)
//     }

//     #[allow(clippy::type_complexity)]
//     pub fn generate_msm_inputs<A>(
//         size: usize,
//     ) -> (
//         Vec<<A::Projective as ProjectiveCurve>::Affine>,
//         Vec<<A::ScalarField as PrimeField>::BigInt>,
//     )
//     where
//         A: AffineCurve,
//     {
//         let mut rng = get_rng();
//         let scalar_vec = (0..size)
//             .map(|_| A::ScalarField::rand(&mut rng).into_repr())
//             .collect();
//         let point_vec = (0..size)
//             .map(|_| A::Projective::rand(&mut rng))
//             .collect::<Vec<_>>();
//         (
//             <A::Projective as ProjectiveCurve>::batch_normalization_into_affine(&point_vec),
//             scalar_vec,
//         )
//     }

//     #[test]
//     fn test_inverses() {
//         let mut rng = get_rng();
//         let fp = (0..1_000_000)
//             .map(|_| Fp::rand(&mut rng))
//             .collect::<Vec<Fp>>();
//         let now = std::time::Instant::now();
//         for f in fp {
//             f.inverse().unwrap();
//         }
//         dbg!(now.elapsed());
//     }

//     #[test]
//     fn test_alloc() {
//         use ark_ff::Zero;

//         let c = 13;
//         let zero: GroupProjective<PallasParameters> = GroupProjective::zero();

//         {
//             let now = std::time::Instant::now();
//             let mut buckets_per_window = vec![vec![zero; (1 << c) - 1]; 20];
//             // let mut buckets_per_window = vec![vec![None::<G::Projective>; (1 << c) - 1]; window_starts.len()];
//             // let buckets_per_window2 = buckets_per_window.clone();
//             // let buckets_per_window3 = buckets_per_window.clone();
//             // let buckets_per_window4 = buckets_per_window.clone();
//             eprintln!("ICI time to alloc buckets: {:?}", now.elapsed());
//         }
//     }

//     #[test]
//     fn test_name() {
//         rayon::ThreadPoolBuilder::new().num_threads(32).build_global().unwrap();

//         // let (mut points, scalars) = generate_msm_inputs::<Pallas>(100_000);
//         let (mut points, scalars) = generate_msm_inputs::<Pallas>(65536);
//         // dbg!(inputs.len());

//         let now = std::time::Instant::now();
//         let result = ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
//             &points,
//             &scalars,
//         ).into_affine();
//         let elapsed = now.elapsed();
//         let good = result;
//         // assert_result(&result);
//         dbg!(result, elapsed);

//         let now = std::time::Instant::now();
//         let result = ark_msm::msm::VariableBaseMSM::multi_scalar_mul::<PallasParameters>(
//             &points,
//             &scalars,
//         ).into_affine();
//         let elapsed = now.elapsed();
//         dbg!(result, elapsed);
//         assert_eq!(good, result);
//         // assert_result(&result);

//         let now = std::time::Instant::now();
//         // let result = my_multi_scalar_batch(
//         // let result = my_multi_scalar_batch_max_threads(
//         let result = call_msm(
//             &points,
//             &scalars,
//         ).into_affine();
//         let elapsed = now.elapsed();
//         // assert_result(&result);
//         dbg!(result, elapsed);
//         assert_eq!(good, result);

//         // for (index, v) in (0i32..100).enumerate().rev() {
//         //     println!("index={:?} v={:?}", index, v);
//         // }

//         // self.pendings.iter().copied().enumerate().rev()

//         // let now = std::time::Instant::now();
//         // let result = my_multi_scalar_mul2(
//         //     &points,
//         //     &scalars,
//         // ).into_affine();
//         // let elapsed = now.elapsed();
//         // // assert_result(&result);
//         // dbg!(result, elapsed);
//         // assert_eq!(good, result);
//     }

//     use ark_ff::{One, Zero};

//     use crate::msm::call_msm;

//     struct Batch<'a> {
//         buckets: Vec<GroupAffine<PallasParameters>>,
//         /// (index in `buckets`, is_negative, group)
//         in_batch: Vec<(usize, bool, &'a GroupAffine<PallasParameters>)>,
//         in_batch_busy_buckets: Vec<bool>,
//         // inverse_state: Fp,
//         // inverses: Vec<Fp>,

//         inverses: Option<BatchInverses>,

//         /// (index in `buckets`, is_negative, group)
//         pendings: Vec<(usize, bool, &'a GroupAffine<PallasParameters>)>,
//     }

//     struct BatchInverses {
//         inverse_state: Fp,
//         inverses: Vec<Fp>,
//     }

//     const N_BATCH: usize = 4096;
//     const N_COLLISION: usize = 512;

//     impl<'a> Batch<'a> {
//         pub fn with_capacity(capacity: usize) -> Self {
//             let zero = GroupAffine::zero();
//             Self {
//                 buckets: vec![zero; capacity],
//                 in_batch: Vec::with_capacity(N_BATCH),
//                 in_batch_busy_buckets: vec![false; capacity],
//                 inverses: Some(BatchInverses {
//                     inverse_state: Fp::one(),
//                     inverses: vec![Fp::one(); N_BATCH],
//                 }),
//                 pendings: Vec::with_capacity(N_BATCH),
//             }
//         }

//         fn with_buckets(buckets: Vec<GroupAffine<PallasParameters>>) -> Self {
//             let capacity = buckets.capacity();
//             Self {
//                 buckets,
//                 in_batch: Vec::with_capacity(N_BATCH),
//                 in_batch_busy_buckets: vec![false; capacity],
//                 inverses: Some(BatchInverses {
//                     inverse_state: Fp::one(),
//                     inverses: vec![Fp::one(); N_BATCH],
//                 }),
//                 pendings: Vec::with_capacity(N_BATCH),
//             }
//         }

//         fn add_batch(&mut self, batch: Self) {
//             let mut buckets = std::mem::take(&mut self.buckets);
//             self.add(&mut buckets, batch.buckets.iter());
//             self.buckets = buckets;
//         }

//         fn add_in_bucket(
//             &mut self,
//             bucket: usize,
//             is_negative: bool,
//             g: &'a GroupAffine<PallasParameters>
//         ) {
//             if self.in_batch_busy_buckets[bucket] {
//                 self.pendings.push((bucket, is_negative, g));
//             } else {
//                 self.in_batch_busy_buckets[bucket] = true;
//                 self.in_batch.push((bucket, is_negative, g));
//             }
//         }

//         fn batch1(
//             // &mut self,
//             res: &mut GroupAffine<PallasParameters>,
//             src: &GroupAffine<PallasParameters>,
//             index: usize,
//             inverses: &mut BatchInverses,
//         ) {
//             if res.is_zero() | src.is_zero() {
//                 return;
//             }
//             let mut delta_x = src.x - res.x;
//             if delta_x.is_zero() {
//                 let delta_y = src.y - res.y;
//                 if !delta_y.is_zero() {
//                     return;
//                 }
//                 delta_x = src.y + src.y;
//             }
//             if inverses.inverse_state.is_zero() {
//                 inverses.inverses[index].set_one();
//                 inverses.inverse_state = delta_x;
//             } else {
//                 inverses.inverses[index] = inverses.inverse_state;
//                 inverses.inverse_state *= delta_x
//             }
//         }

//         fn batch2(
//             res: &mut GroupAffine<PallasParameters>,
//             src: &GroupAffine<PallasParameters>,
//             index: usize,
//             inverses: &mut BatchInverses,
//         ) {
//             if res.is_zero() | src.is_zero() {
//                 if !src.is_zero() {
//                     *res = *src;
//                 }
//                 return;
//             }
//             let mut inverse = inverses.inverses[index];
//             inverse *= inverses.inverse_state;
//             let mut delta_x = src.x - res.x;
//             let mut delta_y = src.y - res.y;
//             if delta_x.is_zero() {
//                 if !delta_y.is_zero() {
//                     res.set_zero();
//                     return;
//                 }
//                 delta_y = src.x.square();
//                 delta_y = delta_y + delta_y + delta_y;
//                 delta_x = src.y.double();
//             }
//             inverses.inverse_state *= delta_x;
//             let s = delta_y * inverse;
//             let ss = s * s;
//             res.x = ss - src.x - res.x;
//             delta_x = src.x - res.x;
//             res.y = s * delta_x;
//             res.y -= src.y;
//         }

//         fn accumulate(&mut self) {
//             use std::ops::Neg;

//             let mut inverses = self.inverses.take().unwrap();
//             inverses.inverse_state = Fp::one();

//             for (pending_index, (bucket_index, is_neg, group)) in self.in_batch.iter().copied().enumerate() {
//                 let bucket = &mut self.buckets[bucket_index];
//                 let mut group = *group;
//                 if is_neg {
//                     group = group.neg();
//                 }
//                 Self::batch1(bucket, &group, pending_index, &mut inverses);
//             }

//             inverses.inverse_state = inverses.inverse_state.inverse().unwrap();

//             for (pending_index, (bucket_index, is_neg, group)) in self.in_batch.iter().copied().enumerate().rev() {
//                 let bucket = &mut self.buckets[bucket_index];
//                 let mut group = *group;
//                 if is_neg {
//                     group = group.neg();
//                 }
//                 Self::batch2(bucket, &group, pending_index, &mut inverses);
//             }

//             self.in_batch.clear();
//             self.in_batch_busy_buckets.iter_mut().for_each(|b| *b = false);

//             self.pendings.retain(|(bucket, is_neg, g)| {
//                 if self.in_batch_busy_buckets[*bucket] {
//                     return true;
//                 }
//                 self.in_batch_busy_buckets[*bucket] = true;
//                 self.in_batch.push((*bucket, *is_neg, g));
//                 false
//             });

//             self.inverses = Some(inverses);
//         }

//         fn add<'b, S>(
//             &mut self,
//             res: &mut [GroupAffine<PallasParameters>],
//             src: S,
//         )
//         where
//             S: Iterator<Item = &'b GroupAffine<PallasParameters>> + Clone + DoubleEndedIterator + ExactSizeIterator,
//         {
//             let mut inverses = self.inverses.take().unwrap();
//             inverses.inverse_state = Fp::one();

//             let src2 = src.clone().into_iter();
//             for (index, (res, point)) in res.iter_mut().zip(src2).enumerate() {
//                 Self::batch1(res, point, index, &mut inverses);
//             }

//             inverses.inverse_state = inverses.inverse_state.inverse().unwrap();

//             for (index, (res, point)) in res.iter_mut().zip(src).enumerate().rev() {
//                 Self::batch2(res, point, index, &mut inverses);
//             }

//             self.inverses = Some(inverses);
//         }
//     }

//     pub fn my_multi_scalar_batch(
//         bases: &[GroupAffine<PallasParameters>],
//         scalars: &[BigInteger256],
//     ) -> GroupProjective<PallasParameters> {
//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};
//         // panic!();

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = if size < 32 {
//             3
//         } else {
//             ln_without_floats(size) + 2
//         };
//         dbg!(c);

//         let num_bits = <<GroupAffine::<PallasParameters> as AffineCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         // let fr_one: BigInteger256 = <<GroupAffine::<PallasParameters> as AffineCurve>::ScalarField>::one().into_repr();

//         let zero = GroupProjective::zero();
//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         dbg!(&window_starts, window_starts.len(), num_bits);

//         let total = 1 << c;
//         let half = total >> 1;

//         #[derive(Copy, Clone)]
//         struct Digits {
//             n: u32,
//         }

//         let now = std::time::Instant::now();
//         let digits = scalars.par_iter().map(|scalar| {
//             let mut scalar = *scalar;
//             let mut carry = 0;
//             window_starts.iter().map(|_win_start| {
//                 let mut digits = scalar.to_64x4()[0] % (1 << c);
//                 digits += carry;
//                 if digits > half {
//                     digits = total - digits;
//                     carry = 1;
//                 } else {
//                     carry = 0;
//                 }
//                 let res = Digits {
//                     n: digits as u32 | ((carry as u32) << 31),
//                 };
//                 scalar.divn(c as u32);
//                 res
//             }).collect::<Vec<_>>()
//         }).collect::<Vec<_>>();
//         eprintln!("digits pre-compute time: {:?}", now.elapsed());

//         let window_sums: Vec<_> = window_starts
//             .par_iter()
//             .copied()
//             .enumerate()
//             .map(|(w_index, w_start)| {

//                 let now = std::time::Instant::now();
//                 let mut batch = Batch::with_capacity(1 << (c - 1));
//                 let elapsed_alloc = now.elapsed();
//                 let now = std::time::Instant::now();

//                 let mut nzeros = 0;
//                 let mut nis_neg = 0;

//                 digits.iter().zip(bases).for_each(|(scalar, base)| {
//                     let Digits { n: digits } = scalar[w_index];

//                     let is_neg = (digits >> 31) != 0;
//                     let digits = ((digits as u32) & ((-1i32 as u32) >> 1)) as usize;

//                     let Some(digits) = digits.checked_sub(1) else {
//                         nzeros += 1;
//                         return;
//                     };

//                     if is_neg {
//                         nis_neg += 1;
//                     }

//                     batch.add_in_bucket(digits, is_neg, base);

//                     if batch.in_batch.len() >= N_BATCH || batch.pendings.len() >= N_COLLISION {
//                         batch.accumulate();
//                     }
//                 });

//                 while !batch.in_batch.is_empty() || !batch.pendings.is_empty() {
//                     batch.accumulate();
//                 }

//                 eprintln!(
//                     "total alloc: {:?} accum: {:?} nzeros: {:?} nis_neg:{:?} in_batch_cap: {:?} pendings_cap: {:?}",
//                     elapsed_alloc, now.elapsed(), nzeros, nis_neg, batch.in_batch.capacity(), batch.pendings.capacity(),
//                 );

//                 let mut res = zero;
//                 let mut running_sum = GroupProjective::zero();
//                 batch.buckets.iter().rev().for_each(|b| {
//                     running_sum.add_assign_mixed(b);
//                     res += &running_sum;
//                 });
//                 res
//             })
//             .collect();

//         // We store the sum for the lowest window.
//         let lowest = *window_sums.first().unwrap();

//         // We're traversing windows from high to low.
//         lowest
//             + &window_sums[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             })
//     }

//     pub fn my_multi_scalar_batch_max_threads(
//         bases: &[GroupAffine<PallasParameters>],
//         scalars: &[BigInteger256],
//     ) -> GroupProjective<PallasParameters> {

//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};

//         struct BatchPerThread<'a> {
//             buckets: Vec<Vec<GroupAffine<PallasParameters>>>,
//             /// (index in `buckets`, is_negative, group)
//             in_batch: Vec<(usize, usize, bool, &'a GroupAffine<PallasParameters>)>,
//             in_batch_busy_buckets: Vec<Vec<bool>>,
//             // inverse_state: Fp,
//             // inverses: Vec<Fp>,

//             inverses: Option<BatchInverses>,

//             /// (index in `buckets`, is_negative, group)
//             pendings: Vec<(usize, usize, bool, &'a GroupAffine<PallasParameters>)>,
//         }

//         struct BatchInverses {
//             inverse_state: Fp,
//             inverses: Vec<Fp>,
//         }

//         const N_BATCH: usize = 4096;
//         const N_COLLISION: usize = 512;

//         const N_WINDOWS: usize = 20;

//         impl<'a> BatchPerThread<'a> {
//             pub fn with_capacity(capacity: usize) -> Self {
//                 let zero = GroupAffine::zero();
//                 Self {
//                     buckets: vec![vec![zero; capacity]; N_WINDOWS],
//                     in_batch: Vec::with_capacity(N_BATCH),
//                     in_batch_busy_buckets: vec![vec![false; capacity]; N_WINDOWS],
//                     inverses: Some(BatchInverses {
//                         inverse_state: Fp::one(),
//                         inverses: vec![Fp::one(); N_BATCH],
//                     }),
//                     pendings: Vec::with_capacity(N_BATCH),
//                 }
//             }

//             fn add_in_bucket(
//                 &mut self,
//                 window: usize,
//                 bucket: usize,
//                 is_negative: bool,
//                 g: &'a GroupAffine<PallasParameters>
//             ) {
//                 if self.in_batch_busy_buckets[window][bucket] {
//                     self.pendings.push((window, bucket, is_negative, g));
//                 } else {
//                     self.in_batch_busy_buckets[window][bucket] = true;
//                     self.in_batch.push((window, bucket, is_negative, g));
//                 }
//             }

//             fn batch1(
//                 // &mut self,
//                 res: &mut GroupAffine<PallasParameters>,
//                 src: &GroupAffine<PallasParameters>,
//                 index: usize,
//                 inverses: &mut BatchInverses,
//             ) {
//                 if res.is_zero() | src.is_zero() {
//                     return;
//                 }
//                 let mut delta_x = src.x - res.x;
//                 if delta_x.is_zero() {
//                     let delta_y = src.y - res.y;
//                     if !delta_y.is_zero() {
//                         return;
//                     }
//                     delta_x = src.y + src.y;
//                 }
//                 if inverses.inverse_state.is_zero() {
//                     inverses.inverses[index].set_one();
//                     inverses.inverse_state = delta_x;
//                 } else {
//                     inverses.inverses[index] = inverses.inverse_state;
//                     inverses.inverse_state *= delta_x
//                 }
//             }

//             fn batch2(
//                 res: &mut GroupAffine<PallasParameters>,
//                 src: &GroupAffine<PallasParameters>,
//                 index: usize,
//                 inverses: &mut BatchInverses,
//             ) {
//                 if res.is_zero() | src.is_zero() {
//                     if !src.is_zero() {
//                         *res = *src;
//                     }
//                     return;
//                 }
//                 let mut inverse = inverses.inverses[index];
//                 inverse *= inverses.inverse_state;
//                 let mut delta_x = src.x - res.x;
//                 let mut delta_y = src.y - res.y;
//                 if delta_x.is_zero() {
//                     if !delta_y.is_zero() {
//                         res.set_zero();
//                         return;
//                     }
//                     delta_y = src.x.square();
//                     delta_y = delta_y + delta_y + delta_y;
//                     delta_x = src.y.double();
//                 }
//                 inverses.inverse_state *= delta_x;
//                 let s = delta_y * inverse;
//                 let ss = s * s;
//                 res.x = ss - src.x - res.x;
//                 delta_x = src.x - res.x;
//                 res.y = s * delta_x;
//                 res.y -= src.y;
//             }

//             fn accumulate(&mut self) {
//                 use std::ops::Neg;

//                 let mut inverses = self.inverses.take().unwrap();
//                 inverses.inverse_state = Fp::one();

//                 for (pending_index, (window_index, bucket_index, is_neg, group)) in self.in_batch.iter().copied().enumerate() {
//                     let bucket = &mut self.buckets[window_index][bucket_index];
//                     let mut group = *group;
//                     if is_neg {
//                         group = group.neg();
//                     }
//                     Self::batch1(bucket, &group, pending_index, &mut inverses);
//                 }

//                 inverses.inverse_state = inverses.inverse_state.inverse().unwrap();

//                 for (pending_index, (window_index, bucket_index, is_neg, group)) in self.in_batch.iter().copied().enumerate().rev() {
//                     let bucket = &mut self.buckets[window_index][bucket_index];
//                     let mut group = *group;
//                     if is_neg {
//                         group = group.neg();
//                     }
//                     Self::batch2(bucket, &group, pending_index, &mut inverses);
//                 }

//                 self.in_batch.clear();
//                 self.in_batch_busy_buckets.iter_mut().for_each(|vec| {
//                     vec.iter_mut().for_each(|b| { *b = false });
//                 });

//                 self.pendings.retain(|(window, bucket, is_neg, g)| {
//                     if self.in_batch_busy_buckets[*window][*bucket] {
//                         return true;
//                     }
//                     self.in_batch_busy_buckets[*window][*bucket] = true;
//                     self.in_batch.push((*window, *bucket, *is_neg, g));
//                     false
//                 });

//                 self.inverses = Some(inverses);
//             }

//             fn add<'b, S>(
//                 &mut self,
//                 res: &mut [GroupAffine<PallasParameters>],
//                 src: S,
//             )
//             where
//                 S: Iterator<Item = &'b GroupAffine<PallasParameters>> + Clone + DoubleEndedIterator + ExactSizeIterator,
//             {
//                 let mut inverses = self.inverses.take().unwrap();
//                 inverses.inverse_state = Fp::one();

//                 let src2 = src.clone().into_iter();
//                 for (index, (res, point)) in res.iter_mut().zip(src2).enumerate() {
//                     Self::batch1(res, point, index, &mut inverses);
//                 }

//                 inverses.inverse_state = inverses.inverse_state.inverse().unwrap();

//                 for (index, (res, point)) in res.iter_mut().zip(src).enumerate().rev() {
//                     Self::batch2(res, point, index, &mut inverses);
//                 }

//                 self.inverses = Some(inverses);
//             }
//         }

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = if size < 32 {
//             3
//         } else {
//             ln_without_floats(size) + 2
//         };

//         let total = 1 << c;
//         let half = total >> 1;

//         #[derive(Copy, Clone)]
//         struct Digits {
//             n: u32,
//         }

//         let num_bits = <<GroupAffine::<PallasParameters> as AffineCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         // let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         // let fr_one = G::ScalarField::one().into_repr();

//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         let now = std::time::Instant::now();
//         let digits = scalars.par_iter().map(|scalar| {
//             let mut scalar = *scalar;
//             let mut carry = 0;
//             window_starts.iter().map(|_win_start| {
//                 let mut digits = scalar.to_64x4()[0] % (1 << c);
//                 digits += carry;
//                 if digits > half {
//                     digits = total - digits;
//                     carry = 1;
//                 } else {
//                     carry = 0;
//                 }
//                 let res = Digits {
//                     n: digits as u32 | ((carry as u32) << 31),
//                 };
//                 scalar.divn(c as u32);
//                 res
//             }).collect::<Vec<_>>()
//         }).collect::<Vec<_>>();
//         eprintln!("digits pre-compute time: {:?}", now.elapsed());

//         let zero = GroupProjective::zero();

//         let num_threads = rayon::current_num_threads();
//         let n_per_thread = (size / num_threads) + 1;

//         let now = std::time::Instant::now();

//         let mut buckets_per_thread = (0..rayon::current_num_threads()).into_par_iter().map(|thread_index| {
//             let now = std::time::Instant::now();
//             let mut batch = BatchPerThread::with_capacity(1 << (c - 1));
//             // let mut buckets_per_window = (0..window_starts.len()).map(|_| {
//             //     ListOfBuckets::with_capacity(1 << (c - 1))
//             // }).collect::<Vec<_>>();
//             // let mut is_initialized = vec![vec![false; 1 << (c - 1)]; window_starts.len()];

//             // let now = std::time::Instant::now();
//             eprintln!("[{:?}] time to alloc buckets: {:?}", thread_index, now.elapsed());
//             let now = std::time::Instant::now();

//             let thread_start = thread_index * n_per_thread;
//             let thread_end = (thread_index + 1) * n_per_thread;

//             // let scalars = &scalars[thread_start..];
//             let bases = &bases[thread_start..];
//             let scalars = &digits[thread_start..];

//             for (scalar, base) in scalars.iter().zip(bases).take(n_per_thread) {
//                 for (index, win_start) in window_starts.iter().copied().enumerate() {
//                     let Digits { n: digits } = scalar[index];

//                     let is_neg = (digits >> 31) != 0;
//                     let digits = ((digits as u32) & ((-1i32 as u32) >> 1)) as usize;

//                     let Some(digits) = digits.checked_sub(1) else {
//                         continue;
//                     };

//                     batch.add_in_bucket(index, digits, is_neg, base);

//                     if batch.in_batch.len() >= N_BATCH || batch.pendings.len() >= N_COLLISION {
//                         batch.accumulate();
//                     }
//                 }
//             }

//             while !batch.in_batch.is_empty() || !batch.pendings.is_empty() {
//                 batch.accumulate();
//             }

//             eprintln!("[{:?}] time to add_assign_mixed: {:?}", thread_index, now.elapsed());

//             batch
//         }).collect::<Vec<_>>();
//         eprintln!("time to add_assign_mixed: {:?}", now.elapsed());

//         let mut buckets_per_window = buckets_per_thread.pop().unwrap();

//         dbg!(buckets_per_thread.len());
//         // dbg!(buckets_per_window.len());

//         let now = std::time::Instant::now();

//         let pendings = buckets_per_window.buckets.into_iter().map(|per_window| {
//             Mutex::new(Some(Batch::with_buckets(per_window)))
//         }).collect::<Vec<_>>();

//         use crossbeam_channel::bounded;

//         let (s, r) = bounded(1000);

//         for (_thread_index, buckets_per_thread) in buckets_per_thread.into_iter().enumerate() {
//             for (window_index, buckets_per_win) in buckets_per_thread.buckets.into_iter().enumerate() {
//                 s.send((window_index, Batch::with_buckets(buckets_per_win))).unwrap();
//             }
//         }

//         let now = std::time::Instant::now();
//         let big_n = AtomicUsize::new(0);
//         let _ = (0..rayon::current_num_threads()).into_par_iter().for_each(|_thread_index| {

//             let mut n = 0;
//             loop {
//                 let Ok((index, mut next)) = r.try_recv() else {
//                     // eprintln!("STOP   {:?} {:?}", n, now.elapsed());
//                     break;
//                 };
//                 let next2 = {
//                     let mut locked = pendings[index].lock().unwrap();
//                     match locked.take() {
//                         Some(pending) => pending,
//                         None => {
//                             *locked = Some(next);
//                             continue;
//                         }
//                     }
//                 };
//                 // let big_n = big_n.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
//                 // let now = std::time::Instant::now();
//                 next.add_batch(next2);
//                 // next.add_list_of_buckets(&next2);
//                 // eprintln!("ADDING {:?} {:?}", big_n, now.elapsed());
//                 n += 1;

//                 // next.iter_mut().zip(next2).for_each(|(accum, for_thread)| {
//                 //     *accum += for_thread;
//                 // });
//                 s.send((index, next)).unwrap();
//             }
//         });
//         eprintln!("time ICI: {:?}", now.elapsed());

//         assert!(s.is_empty());

//         let buckets_per_window = pendings.into_iter().map(|v| v.into_inner().unwrap().unwrap()).collect::<Vec<_>>();

//         let now = std::time::Instant::now();
//         let buckets = buckets_per_window.par_iter().map(|buckets| {
//             let mut res = zero;
//             let mut running_sum = GroupProjective::zero();
//             buckets.buckets.iter().rev().for_each(|b| {
//                 running_sum.add_assign_mixed(b);
//                 res += &running_sum;
//             });
//             res
//         }).collect::<Vec<_>>();
//         eprintln!("time to sum of sums: {:?}", now.elapsed());

//         // let mut res = zero;
//         // let mut running_sum = G::Projective::zero();
//         // buckets.into_iter().rev().for_each(|b| {
//         //     running_sum += &b;
//         //     res += &running_sum;
//         // });
//         // res

//         // We store the sum for the lowest window.
//         let lowest = *buckets.first().unwrap();

//         let now = std::time::Instant::now();
//         // We're traversing windows from high to low.
//         let res = lowest
//             + &buckets[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             });
//         eprintln!("time to fold: {:?}", now.elapsed());

//         res
//     }

//     pub fn my_multi_scalar_orig_with_signed_digits<G: AffineCurve>(
//         bases: &[G],
//         scalars: &[<G::ScalarField as PrimeField>::BigInt],
//     ) -> G::Projective {
//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};
//         // panic!();

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = if size < 32 {
//             3
//         } else {
//             ln_without_floats(size) + 2
//         };
//         dbg!(c);

//         let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         let fr_one = G::ScalarField::one().into_repr();

//         let zero = G::Projective::zero();
//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         dbg!(&window_starts, window_starts.len(), num_bits);

//         let total = 1 << c;
//         let half = total >> 1;

//         #[derive(Copy, Clone)]
//         struct Digits {
//             n: u32,
//         }

//         let now = std::time::Instant::now();
//         let digits = scalars.par_iter().map(|scalar| {
//             let mut scalar = *scalar;
//             let mut carry = 0;
//             window_starts.iter().map(|_win_start| {
//                 let mut digits = scalar.to_64x4()[0] % (1 << c);
//                 digits += carry;
//                 if digits > half {
//                     digits = total - digits;
//                     carry = 1;
//                 } else {
//                     carry = 0;
//                 }
//                 let res = Digits {
//                     n: digits as u32 | ((carry as u32) << 31),
//                 };
//                 scalar.divn(c as u32);
//                 res
//             }).collect::<Vec<_>>()
//         }).collect::<Vec<_>>();
//         eprintln!("digits pre-compute time: {:?}", now.elapsed());

//         // Each window is of size `c`.
//         // We divide up the bits 0..num_bits into windows of size `c`, and
//         // in parallel process each such window.
//         let window_sums: Vec<_> = window_starts
//             .par_iter()
//             .copied()
//             .enumerate()
//             .map(|(w_index, w_start)| {

//                 let mut res = zero;
//                 // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.

//                 // let now = std::time::Instant::now();
//                 let mut buckets = vec![zero; (1 << (c - 1)) - 0];
//                 // eprintln!("allocation time: {:?} n={:?}", now.elapsed(), buckets.len());

//                 digits.iter().zip(bases).for_each(|(scalar, base)| {
//                     let Digits { n: digits } = scalar[w_index];

//                     let is_neg = (digits >> 31) != 0;
//                     let digits = (digits as u32) & ((-1i32 as u32) >> 1);

//                     let Some(digits) = digits.checked_sub(1) else {
//                         return;
//                     };

//                     if is_neg {
//                         buckets[digits as usize].add_assign_mixed(&base.neg());
//                     } else {
//                         buckets[digits as usize].add_assign_mixed(base);
//                     }
//                 });

//                 // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
//                 // This is computed below for b buckets, using 2b curve additions.
//                 //
//                 // We could first normalize `buckets` and then use mixed-addition
//                 // here, but that's slower for the kinds of groups we care about
//                 // (Short Weierstrass curves and Twisted Edwards curves).
//                 // In the case of Short Weierstrass curves,
//                 // mixed addition saves ~4 field multiplications per addition.
//                 // However normalization (with the inversion batched) takes ~6
//                 // field multiplications per element,
//                 // hence batch normalization is a slowdown.

//                 // `running_sum` = sum_{j in i..num_buckets} bucket[j],
//                 // where we iterate backward from i = num_buckets to 0.
//                 let mut running_sum = G::Projective::zero();
//                 buckets.into_iter().rev().for_each(|b| {
//                     running_sum += &b;
//                     res += &running_sum;
//                 });
//                 res
//             })
//             .collect();

//         // We store the sum for the lowest window.
//         let lowest = *window_sums.first().unwrap();

//         // We're traversing windows from high to low.
//         lowest
//             + &window_sums[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             })
//     }

//     struct ListOfBuckets<G: AffineCurve> {
//         buckets: Vec<G::Projective>,
//         is_initialized: Vec<bool>,
//     }

//     impl<G: AffineCurve> ListOfBuckets<G> {
//         fn with_capacity(capacity: usize) -> Self {
//             Self {
//                 buckets: {
//                     let mut vec = Vec::<G::Projective>::with_capacity(capacity);
//                     unsafe { vec.set_len(capacity); }
//                     vec
//                 },
//                 is_initialized: vec![false; capacity],
//             }
//         }

//         fn add_assign_mixed(&mut self, index: usize, g: &G) {
//             if !self.is_initialized[index] {
//                 self.buckets[index] = (*g).into();
//                 self.is_initialized[index] = true;
//             } else {
//                 self.buckets[index].add_assign_mixed(g);
//             }
//         }

//         fn iter_mut(&mut self) -> impl Iterator<Item = (&mut G::Projective, &mut bool)> {
//             self.buckets.iter_mut().zip(self.is_initialized.iter_mut())
//         }

//         fn iter(&self) -> impl Iterator<Item = (&G::Projective, bool)> {
//             self.buckets.iter().zip(self.is_initialized.iter().copied())
//         }

//         fn iter_rev(&self) -> impl Iterator<Item = (&G::Projective, bool)> {
//             self.buckets.iter().rev().zip(self.is_initialized.iter().rev().copied())
//         }

//         fn add_list_of_buckets(&mut self, other: &Self) {
//             self.iter_mut().zip(other.iter()).for_each(|((group, is_init), (other_group, other_is_init))| {
//                 match (*is_init, other_is_init) {
//                     (true, true) => {
//                         *group += other_group;
//                     },
//                     (true, false) => {},
//                     (false, true) => {
//                         *group = *other_group;
//                         *is_init = true;
//                     },
//                     (false, false) => {},
//                 }
//             });
//         }

//         fn counts(&self) -> (usize, usize) {
//             let total = self.is_initialized.len();
//             let n_init = self.is_initialized.iter().filter(|b| **b).count();
//             (n_init, total)
//         }
//     }

//     pub fn my_multi_scalar_mul2<G: AffineCurve>(
//         bases: &[G],
//         scalars: &[<G::ScalarField as PrimeField>::BigInt],
//     ) -> G::Projective {
//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};
//         // panic!();

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = 13;
//         // let c = if size < 32 {
//         //     3
//         // } else {
//         //     ln_without_floats(size) + 2
//         // };

//         let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         let fr_one = G::ScalarField::one().into_repr();

//         let zero = G::Projective::zero();
//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         // dbg!(c, num_bits);
//         // dbg!(&window_starts, window_starts.len(), num_bits);

//         // let mut buckets_per_window = vec![vec![zero; (1 << c) - 1]; window_starts.len()];
//         // let mut buckets = vec![zero; (1 << c) - 1];

//         // dbg!(rayon::current_num_threads());

//         let num_threads = rayon::current_num_threads();
//         let n_per_thread = (size / num_threads) + 1;

//         let now = std::time::Instant::now();

//         dbg!((1 << c) - 1);

//         let mut buckets_per_thread = (0..rayon::current_num_threads()).into_par_iter().map(|thread_index| {
//             // let mut buckets_per_window = vec![vec![zero; 1 << (c - 1)]; window_starts.len()];
//             let mut buckets_per_window = (0..window_starts.len()).map(|_| {
//                 // let mut vec = Vec::<G::Projective>::with_capacity(1 << (c - 1));
//                 // unsafe { vec.set_len(1 << (c - 1)); }
//                 // vec
//                 ListOfBuckets::with_capacity(1 << (c - 1))
//             }).collect::<Vec<_>>();
//             // let mut is_initialized = vec![vec![false; 1 << (c - 1)]; window_starts.len()];

//             let now = std::time::Instant::now();
//             // eprintln!("[{:?}] time to alloc buckets: {:?}", thread_index, now.elapsed());
//             // let now = std::time::Instant::now();

//             let thread_start = thread_index * n_per_thread;
//             let thread_end = (thread_index + 1) * n_per_thread;

//             let scalars = &scalars[thread_start..];
//             let bases = &bases[thread_start..];

//             for (scalar, base) in scalars.iter().zip(bases).take(n_per_thread) {
//                 if scalar == &fr_one {
//                     panic!();
//                 }

//                 let mut carry = 0;

//                 let total = 1 << c;
//                 let half = total >> 1;

//                 for (index, win_start) in window_starts.iter().copied().enumerate() {
//                     let mut scalar = *scalar;
//                     scalar.divn(win_start as u32);

//                     let mut digits = scalar.to_64x4()[0] % (1 << c);
//                     digits += carry;

//                     let buckets = &mut buckets_per_window[index];
//                     // let is_initialized = &mut is_initialized[index];

//                     if digits > half {
//                         digits = total - digits;
//                         carry = 1;

//                         if digits > 0 {
//                             let index = (digits - 1) as usize;
//                             buckets.add_assign_mixed(index, &base.neg());
//                             // if !is_initialized[index] {
//                             //     buckets[index] = base.neg().into();
//                             //     is_initialized[index] = true;
//                             // } else {
//                             //     buckets[index].add_assign_mixed(&base.neg());
//                             // }
//                         }
//                     } else {
//                         carry = 0;
//                         if digits > 0 {
//                             let index = (digits - 1) as usize;
//                             buckets.add_assign_mixed(index, base);
//                             // if !is_initialized[index] {
//                             //     buckets[index] = (*base).into();
//                             //     is_initialized[index] = true;
//                             // } else {
//                             //     buckets[index].add_assign_mixed(base);
//                             // }
//                         }
//                     }
//                 }
//             }

//             eprintln!("[{:?}] time to add_assign_mixed: {:?}", thread_index, now.elapsed());
//             // let now = std::time::Instant::now();
//             // let mut n_not_init = 0;
//             // let mut n_total = 0;

//             // for (buckets, is_init) in buckets_per_window.iter_mut().zip(&is_initialized) {
//             //     for (group, is_init) in buckets.iter_mut().zip(is_init) {
//             //         if !*is_init {
//             //             n_not_init += 1;
//             //             *group = zero;
//             //         }
//             //         n_total += 1;
//             //     }
//             // }
//             // eprintln!("[{:?}] time to set {:?}/{:?} to zero: {:?}", thread_index, n_not_init, n_total, now.elapsed());

//             // for (index, g) in buckets_per_window.iter().enumerate() {
//             //     for (index, g) in g.iter().enumerate() {
//             //         if g.is_zero() {
//             //             eprintln!("ZERO at {:?}", index);
//             //         }
//             //     }
//             // }

//             buckets_per_window
//         }).collect::<Vec<_>>();
//         eprintln!("time to add_assign_mixed: {:?}", now.elapsed());

//         // panic!();

//         // let now = std::time::Instant::now();
//         // let mut buckets_per_window = vec![vec![zero; 1 << (c - 1)]; window_starts.len()];
//         let mut buckets_per_window = buckets_per_thread.pop().unwrap();
//         // let mut buckets_per_window = vec![vec![None::<G::Projective>; 1 << (c - 1)]; window_starts.len()];

//         dbg!(buckets_per_thread.len());
//         dbg!(buckets_per_window.len());

//         let now = std::time::Instant::now();
//         // buckets_per_window.par_iter_mut().for_each(|buckets_per_window| {
//         //     for buckets_per_thread in &buckets_per_thread {
//         //         // dbg!(buckets_per_thread.len()); // 20
//         //         for (i, buckets_per_win) in buckets_per_thread.iter().enumerate() {
//         //             // let buckets_per_window = &mut buckets_per_window[i];
//         //             // dbg!(buckets_per_window.len()); // 8191
//         //             buckets_per_window.iter_mut().zip(buckets_per_win).for_each(|(accum, for_thread)| {
//         //                 *accum += for_thread;
//         //             });
//         //         }
//         //     }
//         // });

//         let pendings = buckets_per_window.into_iter().map(|per_window| {
//             Mutex::new(Some(per_window))
//         }).collect::<Vec<_>>();

//         use crossbeam_channel::bounded;

//         let (s, r) = bounded(1000);

//         for (_thread_index, buckets_per_thread) in buckets_per_thread.into_iter().enumerate() {
//             for (window_index, buckets_per_win) in buckets_per_thread.into_iter().enumerate() {
//                 s.send((window_index, buckets_per_win)).unwrap();
//             }
//         }

//         let now = std::time::Instant::now();
//         let _ = (0..rayon::current_num_threads()).into_par_iter().for_each(|_thread_index| {

//             let mut n = 0;
//             loop {
//                 let Ok((index, mut next)) = r.try_recv() else {
//                     // eprintln!("STOP   {:?} {:?}", n, now.elapsed());
//                     break;
//                 };
//                 let next2 = {
//                     let mut locked = pendings[index].lock().unwrap();
//                     match locked.take() {
//                         Some(pending) => pending,
//                         None => {
//                             *locked = Some(next);
//                             continue;
//                         }
//                     }
//                 };
//                 next.add_list_of_buckets(&next2);
//                 // eprintln!("ADDING {:?} {:?}", n, now.elapsed());
//                 n += 1;

//                 // next.iter_mut().zip(next2).for_each(|(accum, for_thread)| {
//                 //     *accum += for_thread;
//                 // });
//                 s.send((index, next)).unwrap();
//             }
//         });
//         eprintln!("time ICI: {:?}", now.elapsed());

//         assert!(s.is_empty());

//         // let a = n_ran.load(std::sync::atomic::Ordering::Relaxed);
//         // assert_eq!(a, 620);

//         // todo!();

//         // let _ = (0..rayon::current_num_threads()).into_par_iter().map(|thread_index| {
//         // }).collect::<Vec<_>>();

//         // dbg!(buckets_per_thread.len());

//         // for (thread_index, buckets_per_thread) in buckets_per_thread.iter().enumerate() {
//         //     dbg!(buckets_per_thread.len()); // 20
//         //     for (i, buckets_per_win) in buckets_per_thread.iter().enumerate() {
//         //         let buckets_per_window = &mut buckets_per_window[i];
//         //         // dbg!(buckets_per_window.len()); // 8191 or 4096
//         //         buckets_per_window.iter_mut().zip(buckets_per_win).for_each(|(accum, for_thread)| {
//         //             *accum += for_thread;
//         //         });
//         //     }
//         // }

//         // for buckets_per_thread in buckets_per_thread {
//         //     // dbg!(buckets_per_thread.len()); // 20
//         //     for (i, buckets_per_win) in buckets_per_thread.iter().enumerate() {
//         //         let buckets_per_window = &mut buckets_per_window[i];
//         //         // dbg!(buckets_per_window.len()); // 8191 or 4096
//         //         buckets_per_window.iter_mut().zip(buckets_per_win).for_each(|(accum, for_thread)| {
//         //             *accum += for_thread;
//         //         });
//         //     }
//         // }
//         // eprintln!("time to accumulate: {:?}", now.elapsed());

//         // let now = std::time::Instant::now();
//         // let mut buckets_per_window = vec![vec![zero; (1 << c) - 1]; window_starts.len()];
//         // for buckets_per_thread in buckets_per_thread {
//         //     dbg!(buckets_per_thread.len()); // 20
//         //     for (i, buckets_per_win) in buckets_per_thread.iter().enumerate() {
//         //         let buckets_per_window = &mut buckets_per_window[i];
//         //         // dbg!(buckets_per_window.len()); // 8191
//         //         buckets_per_window.iter_mut().zip(buckets_per_win).for_each(|(accum, for_thread)| {
//         //             *accum += for_thread;
//         //         });
//         //     }
//         // }
//         // eprintln!("time to accumulate: {:?}", now.elapsed());

//         // let buckets_per_window = buckets_per_thread.iter().map(|buckets_per_window| {

//         // }).collect::<Vec<_>>();

//         // for (scalar, base) in scalars_and_bases_iter.clone() {
//         //     if scalar == &fr_one {
//         //         panic!();
//         //     }
//         //     for (index, win_start) in window_starts.iter().copied().enumerate() {
//         //         let mut scalar = *scalar;
//         //         scalar.divn(win_start as u32);
//         //         let scalar = scalar.to_64x4()[0] % (1 << c);
//         //         if scalar != 0 {
//         //             let buckets = &mut buckets_per_window[index];
//         //             buckets[(scalar - 1) as usize].add_assign_mixed(base);
//         //         }
//         //     }
//         // }
//         // eprintln!("time to add_assign_mixed: {:?}", now.elapsed());

//         // dbg!(buckets_per_window.len());

//         let buckets_per_window = pendings.into_iter().map(|v| v.into_inner().unwrap().unwrap()).collect::<Vec<_>>();

//         let now = std::time::Instant::now();
//         let buckets = buckets_per_window.par_iter().map(|buckets| {
//             let mut res = zero;
//             let mut running_sum = G::Projective::zero();
//             buckets.iter_rev().for_each(|(b, is_init)| {
//                 if is_init {
//                     running_sum += b;
//                 }
//                 res += &running_sum;
//             });
//             res
//         }).collect::<Vec<_>>();
//         eprintln!("time to sum of sums: {:?}", now.elapsed());

//         // let mut res = zero;
//         // let mut running_sum = G::Projective::zero();
//         // buckets.into_iter().rev().for_each(|b| {
//         //     running_sum += &b;
//         //     res += &running_sum;
//         // });
//         // res

//         // We store the sum for the lowest window.
//         let lowest = *buckets.first().unwrap();

//         let now = std::time::Instant::now();
//         // We're traversing windows from high to low.
//         let res = lowest
//             + &buckets[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             });
//         eprintln!("time to fold: {:?}", now.elapsed());

//         res

//         // todo!()

//         // // Each window is of size `c`.
//         // // We divide up the bits 0..num_bits into windows of size `c`, and
//         // // in parallel process each such window.
//         // let window_sums: Vec<_> = window_starts
//         //     .into_par_iter()
//         //     .map(|w_start| {

//         //         let mut res = zero;
//         //         // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.
//         //         let mut buckets = vec![zero; (1 << c) - 1];
//         //         // This clone is cheap, because the iterator contains just a
//         //         // pointer and an index into the original vectors.
//         //         scalars_and_bases_iter.clone().for_each(|(&scalar, base)| {
//         //             if scalar == fr_one {
//         //                 // We only process unit scalars once in the first window.
//         //                 if w_start == 0 {
//         //                     res.add_assign_mixed(base);
//         //                 }
//         //             } else {
//         //                 let mut scalar = scalar;

//         //                 // We right-shift by w_start, thus getting rid of the
//         //                 // lower bits.
//         //                 scalar.divn(w_start as u32);

//         //                 // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
//         //                 let scalar = scalar.to_64x4()[0] % (1 << c);

//         //                 // If the scalar is non-zero, we update the corresponding
//         //                 // bucket.
//         //                 // (Recall that `buckets` doesn't have a zero bucket.)
//         //                 if scalar != 0 {
//         //                     buckets[(scalar - 1) as usize].add_assign_mixed(base);
//         //                 }
//         //             }
//         //         });

//         //         // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
//         //         // This is computed below for b buckets, using 2b curve additions.
//         //         //
//         //         // We could first normalize `buckets` and then use mixed-addition
//         //         // here, but that's slower for the kinds of groups we care about
//         //         // (Short Weierstrass curves and Twisted Edwards curves).
//         //         // In the case of Short Weierstrass curves,
//         //         // mixed addition saves ~4 field multiplications per addition.
//         //         // However normalization (with the inversion batched) takes ~6
//         //         // field multiplications per element,
//         //         // hence batch normalization is a slowdown.

//         //         // `running_sum` = sum_{j in i..num_buckets} bucket[j],
//         //         // where we iterate backward from i = num_buckets to 0.
//         //         let mut running_sum = G::Projective::zero();
//         //         buckets.into_iter().rev().for_each(|b| {
//         //             running_sum += &b;
//         //             res += &running_sum;
//         //         });
//         //         res
//         //     })
//         //     .collect();

//         // // We store the sum for the lowest window.
//         // let lowest = *window_sums.first().unwrap();

//         // // We're traversing windows from high to low.
//         // lowest
//         //     + &window_sums[1..]
//         //     .iter()
//         //     .rev()
//         //     .fold(zero, |mut total, sum_i| {
//         //         total += sum_i;
//         //         for _ in 0..c {
//         //             total.double_in_place();
//         //         }
//         //         total
//         //     })
//     }

//     pub fn my_multi_scalar_mul<G: AffineCurve>(
//         bases: &[G],
//         scalars: &[<G::ScalarField as PrimeField>::BigInt],
//     ) -> G::Projective {
//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};
//         // panic!();

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = if size < 32 {
//             3
//         } else {
//             ln_without_floats(size) + 2
//         };
//         dbg!(c);

//         let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         let fr_one = G::ScalarField::one().into_repr();

//         let zero = G::Projective::zero();
//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         // dbg!(&window_starts, window_starts.len(), num_bits);

//         // Each window is of size `c`.
//         // We divide up the bits 0..num_bits into windows of size `c`, and
//         // in parallel process each such window.
//         let window_sums: Vec<_> = window_starts
//             .into_par_iter()
//             .map(|w_start| {

//                 let mut res = zero;
//                 // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.

//                 let mut buckets = ListOfBuckets::with_capacity((1 << c) - 1);
//                 // let mut buckets = vec![zero; (1 << c) - 1];
//                 // This clone is cheap, because the iterator contains just a
//                 // pointer and an index into the original vectors.
//                 scalars_and_bases_iter.clone().for_each(|(&scalar, base)| {
//                     if scalar == fr_one {
//                         // We only process unit scalars once in the first window.
//                         if w_start == 0 {
//                             res.add_assign_mixed(base);
//                         }
//                     } else {
//                         let mut scalar = scalar;

//                         // We right-shift by w_start, thus getting rid of the
//                         // lower bits.
//                         scalar.divn(w_start as u32);

//                         // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
//                         let scalar = scalar.to_64x4()[0] % (1 << c);

//                         // If the scalar is non-zero, we update the corresponding
//                         // bucket.
//                         // (Recall that `buckets` doesn't have a zero bucket.)
//                         if scalar != 0 {
//                             buckets.add_assign_mixed((scalar - 1) as usize, base);
//                             // buckets[(scalar - 1) as usize].add_assign_mixed(base);
//                         }
//                     }
//                 });

//                 // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
//                 // This is computed below for b buckets, using 2b curve additions.
//                 //
//                 // We could first normalize `buckets` and then use mixed-addition
//                 // here, but that's slower for the kinds of groups we care about
//                 // (Short Weierstrass curves and Twisted Edwards curves).
//                 // In the case of Short Weierstrass curves,
//                 // mixed addition saves ~4 field multiplications per addition.
//                 // However normalization (with the inversion batched) takes ~6
//                 // field multiplications per element,
//                 // hence batch normalization is a slowdown.

//                 // `running_sum` = sum_{j in i..num_buckets} bucket[j],
//                 // where we iterate backward from i = num_buckets to 0.
//                 let mut running_sum = G::Projective::zero();
//                 buckets.iter_rev().for_each(|(b, is_init)| {
//                     if is_init {
//                         running_sum += b;
//                     }
//                     res += &running_sum;
//                 });
//                 res
//             })
//             .collect();

//         // We store the sum for the lowest window.
//         let lowest = *window_sums.first().unwrap();

//         // We're traversing windows from high to low.
//         lowest
//             + &window_sums[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             })
//     }

//     pub fn my_multi_scalar_mul_orig<G: AffineCurve>(
//         bases: &[G],
//         scalars: &[<G::ScalarField as PrimeField>::BigInt],
//     ) -> G::Projective {
//         use ark_ff::BigInteger;
//         use ark_ff::{One, Zero, FpParameters};
//         // panic!();

//         let size = std::cmp::min(bases.len(), scalars.len());
//         let scalars = &scalars[..size];
//         let bases = &bases[..size];
//         let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

//         let c = if size < 32 {
//             3
//         } else {
//             ln_without_floats(size) + 2
//         };
//         dbg!(c);

//         let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
//         let fr_one = G::ScalarField::one().into_repr();

//         let zero = G::Projective::zero();
//         let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

//         dbg!(&window_starts, window_starts.len(), num_bits);

//         // Each window is of size `c`.
//         // We divide up the bits 0..num_bits into windows of size `c`, and
//         // in parallel process each such window.
//         let window_sums: Vec<_> = window_starts
//             .into_par_iter()
//             .map(|w_start| {

//                 let mut res = zero;
//                 // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.
//                 let mut buckets = vec![zero; (1 << c) - 1];
//                 // This clone is cheap, because the iterator contains just a
//                 // pointer and an index into the original vectors.
//                 scalars_and_bases_iter.clone().for_each(|(&scalar, base)| {
//                     if scalar == fr_one {
//                         // We only process unit scalars once in the first window.
//                         if w_start == 0 {
//                             res.add_assign_mixed(base);
//                         }
//                     } else {
//                         let mut scalar = scalar;

//                         // We right-shift by w_start, thus getting rid of the
//                         // lower bits.
//                         scalar.divn(w_start as u32);

//                         // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
//                         let scalar = scalar.to_64x4()[0] % (1 << c);

//                         // If the scalar is non-zero, we update the corresponding
//                         // bucket.
//                         // (Recall that `buckets` doesn't have a zero bucket.)
//                         if scalar != 0 {
//                             buckets[(scalar - 1) as usize].add_assign_mixed(base);
//                         }
//                     }
//                 });

//                 // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
//                 // This is computed below for b buckets, using 2b curve additions.
//                 //
//                 // We could first normalize `buckets` and then use mixed-addition
//                 // here, but that's slower for the kinds of groups we care about
//                 // (Short Weierstrass curves and Twisted Edwards curves).
//                 // In the case of Short Weierstrass curves,
//                 // mixed addition saves ~4 field multiplications per addition.
//                 // However normalization (with the inversion batched) takes ~6
//                 // field multiplications per element,
//                 // hence batch normalization is a slowdown.

//                 // `running_sum` = sum_{j in i..num_buckets} bucket[j],
//                 // where we iterate backward from i = num_buckets to 0.
//                 let mut running_sum = G::Projective::zero();
//                 buckets.into_iter().rev().for_each(|b| {
//                     running_sum += &b;
//                     res += &running_sum;
//                 });
//                 res
//             })
//             .collect();

//         // We store the sum for the lowest window.
//         let lowest = *window_sums.first().unwrap();

//         // We're traversing windows from high to low.
//         lowest
//             + &window_sums[1..]
//             .iter()
//             .rev()
//             .fold(zero, |mut total, sum_i| {
//                 total += sum_i;
//                 for _ in 0..c {
//                     total.double_in_place();
//                 }
//                 total
//             })
//     }

//     fn ln_without_floats(a: usize) -> usize {
//         // log2(a) * ln(2)

//         (log2(a) * 69 / 100) as usize
//     }

//     fn log2(x: usize) -> u32 {
//         if x == 0 {
//             0
//         } else if x.is_power_of_two() {
//             1usize.leading_zeros() - x.leading_zeros()
//         } else {
//             0usize.leading_zeros() - x.leading_zeros()
//         }
//     }

// }

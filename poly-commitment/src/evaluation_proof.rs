use crate::msm::call_msm;
use crate::{commitment::*, srs::endos};
use crate::{srs::SRS, PolynomialsToCombine, SRS as _};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_poly::{EvaluationDomain, Evaluations};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::{math, ExtendedDensePolynomial};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::iter::Iterator;

// A formal sum of the form
// `s_0 * p_0 + ... s_n * p_n`
// where each `s_i` is a scalar and each `p_i` is a polynomial.
#[derive(Default)]
struct ScaledChunkedPolynomial<F, P>(Vec<(F, P)>);

pub enum DensePolynomialOrEvaluations<'a, F: FftField, D: EvaluationDomain<F>> {
    DensePolynomial(&'a DensePolynomial<F>),
    Evaluations(&'a Evaluations<F, D>, D),
}

impl<F, P> ScaledChunkedPolynomial<F, P> {
    fn add_poly(&mut self, scale: F, p: P) {
        self.0.push((scale, p))
    }
}

impl<'a, F: Field> ScaledChunkedPolynomial<F, &'a [F]> {
    fn to_dense_polynomial(&self) -> DensePolynomial<F> {
        let mut res = DensePolynomial::<F>::zero();

        let scaled: Vec<_> = self
            .0
            .par_iter()
            .map(|(scale, segment)| {
                let scale = *scale;
                let v = segment.par_iter().map(|x| scale * *x).collect();
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();

        for p in scaled {
            res += &p;
        }

        res
    }
}

/// Combine the polynomials using `polyscale`, creating a single unified polynomial to open.
pub fn combine_polys<G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>>(
    plnms: PolynomialsToCombine<G, D>, // vector of polynomial with optional degree bound and commitment randomness
    polyscale: G::ScalarField,         // scaling factor for polynoms
    srs_length: usize,
) -> (DensePolynomial<G::ScalarField>, G::ScalarField) {
    let mut plnm = ScaledChunkedPolynomial::<G::ScalarField, &[G::ScalarField]>::default();
    let mut plnm_evals_part = {
        // For now just check that all the evaluation polynomials are the same degree so that we
        // can do just a single FFT.
        // Furthermore we check they have size less than the SRS size so we don't have to do chunking.
        // If/when we change this, we can add more complicated code to handle different degrees.
        let degree = plnms
            .iter()
            .fold(None, |acc, (p, _)| match p {
                DensePolynomialOrEvaluations::DensePolynomial(_) => acc,
                DensePolynomialOrEvaluations::Evaluations(_, d) => {
                    if let Some(n) = acc {
                        assert_eq!(n, d.size());
                    }
                    Some(d.size())
                }
            })
            .unwrap_or(0);
        vec![G::ScalarField::zero(); degree]
    };

    let mut omega = G::ScalarField::zero();
    let mut scale = G::ScalarField::one();

    // iterating over polynomials in the batch
    for (p_i, omegas) in plnms {
        match p_i {
            DensePolynomialOrEvaluations::Evaluations(evals_i, sub_domain) => {
                let stride = evals_i.evals.len() / sub_domain.size();
                let evals = &evals_i.evals;
                plnm_evals_part
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, x)| {
                        *x += scale * evals[i * stride];
                    });
                for j in 0..omegas.elems.len() {
                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                }
            }

            DensePolynomialOrEvaluations::DensePolynomial(p_i) => {
                let mut offset = 0;
                // iterating over chunks of the polynomial
                for j in 0..omegas.elems.len() {
                    let segment = &p_i.coeffs[std::cmp::min(offset, p_i.coeffs.len())
                        ..std::cmp::min(offset + srs_length, p_i.coeffs.len())];
                    plnm.add_poly(scale, segment);

                    omega += &(omegas.elems[j] * scale);
                    scale *= &polyscale;
                    offset += srs_length;
                }
            }
        }
    }

    let mut plnm = plnm.to_dense_polynomial();
    if !plnm_evals_part.is_empty() {
        let n = plnm_evals_part.len();
        let max_poly_size = srs_length;
        let num_chunks = if n == 0 {
            1
        } else {
            n / max_poly_size + if n % max_poly_size == 0 { 0 } else { 1 }
        };
        plnm += &Evaluations::from_vec_and_domain(plnm_evals_part, D::new(n).unwrap())
            .interpolate()
            .to_chunked_polynomial(num_chunks, max_poly_size)
            .linearize(polyscale);
    }

    (plnm, omega)
}

impl<G: CommitmentCurve> SRS<G> {
    /// This function opens polynomial commitments in batch
    ///     plnms: batch of polynomials to open commitments for with, optionally, max degrees
    ///     elm: evaluation point vector to open the commitments at
    ///     polyscale: polynomial scaling factor for opening commitments in batch
    ///     evalscale: eval scaling factor for opening commitments in batch
    ///     oracle_params: parameters for the random oracle argument
    ///     RETURN: commitment opening proof
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::many_single_char_names)]
    pub fn open<EFqSponge, RNG, D: EvaluationDomain<G::ScalarField>>(
        &self,
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: PolynomialsToCombine<G, D>, // vector of polynomial with commitment randomness
        elm: &[G::ScalarField],            // vector of evaluation points
        polyscale: G::ScalarField,         // scaling factor for polynoms
        evalscale: G::ScalarField,         // scaling factor for evaluation point powers
        mut sponge: EFqSponge,             // sponge
        rng: &mut RNG,
    ) -> OpeningProof<G>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng,
        G::BaseField: PrimeField,
        G: EndoCurve,
    {
        let (endo_q, endo_r) = endos::<G>();

        let rounds = math::ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        // TODO: Trim this to the degree of the largest polynomial
        let padding = padded_length - self.g.len();
        let mut g = self.g.clone();
        g.extend(vec![G::zero(); padding]);

        let (p, blinding_factor) = combine_polys::<G, D>(plnms, polyscale, self.g.len());

        let rounds = math::ceil_log2(self.g.len());

        // b_j = sum_i r^i elm_i^j
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = G::ScalarField::one();
            let mut res: Vec<G::ScalarField> =
                (0..padded_length).map(|_| G::ScalarField::zero()).collect();
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(G::ScalarField::zero(), |acc, x| acc + x);

        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let t = sponge.challenge_fq();
        let u: G = to_group(group_map, t);

        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![G::ScalarField::zero(); padded_length - a.len()]);

        let mut b = b_init;

        let mut lr = vec![];

        let mut blinders = vec![];

        let mut chals = vec![];
        let mut chal_invs = vec![];

        for _ in 0..rounds {
            let n = g.len() / 2;
            let (g_lo, g_hi) = (g[0..n].to_vec(), g[n..].to_vec());
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            let rand_l = <G::ScalarField as UniformRand>::rand(rng);
            let rand_r = <G::ScalarField as UniformRand>::rand(rng);

            let call_l = || {
                call_msm(
                    &[&g[0..n], &[self.h, u]].concat(),
                    &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
                        .concat()
                        .iter()
                        .map(|x| x.into_repr())
                        .collect::<Vec<_>>(),
                )
                .into_affine()
            };

            let call_r = || {
                call_msm(
                    &[&g[n..], &[self.h, u]].concat(),
                    &[&a[0..n], &[rand_r, inner_prod(a_lo, b_hi)]]
                        .concat()
                        .iter()
                        .map(|x| x.into_repr())
                        .collect::<Vec<_>>(),
                )
                .into_affine()
            };

            let (l, r) = rayon::join(call_l, call_r);

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            let u_pre = squeeze_prechallenge(&mut sponge);
            let u = u_pre.to_field(&endo_r);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            let call_a = || {
                a_hi.par_iter()
                    .zip(a_lo)
                    .map(|(&hi, &lo)| {
                        // lo + u_inv * hi
                        let mut res = hi;
                        res *= u_inv;
                        res += &lo;
                        res
                    })
                    .collect()
            };

            let call_b = || {
                b_lo.par_iter()
                    .zip(b_hi)
                    .map(|(&lo, &hi)| {
                        // lo + u * hi
                        let mut res = hi;
                        res *= u;
                        res += &lo;
                        res
                    })
                    .collect()
            };

            (a, b) = rayon::join(call_a, call_b);

            g = G::combine_one_endo(endo_r, endo_q, &g_lo, &g_hi, u_pre);
        }

        assert!(g.len() == 1);
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((l, r), (u, u_inv))| ((*l) * u_inv) + (*r * u))
            .fold(blinding_factor, |acc, x| acc + x);

        let d = <G::ScalarField as UniformRand>::rand(rng);
        let r_delta = <G::ScalarField as UniformRand>::rand(rng);

        let delta = ((g0.into_projective() + (u.mul(b0))).into_affine().mul(d)
            + self.h.mul(r_delta))
        .into_affine();

        sponge.absorb_g(&[delta]);
        let c = ScalarChallenge(sponge.challenge()).to_field(&endo_r);

        let z1 = a0 * c + d;
        let z2 = c * r_prime + r_delta;

        OpeningProof {
            delta,
            lr,
            z1,
            z2,
            sg: g0,
        }
    }

    /// This function is a debugging helper.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::many_single_char_names)]
    pub fn prover_polynomials_to_verifier_evaluations<D: EvaluationDomain<G::ScalarField>>(
        &self,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[G::ScalarField], // vector of evaluation points
    ) -> Vec<Evaluation<G>>
    where
        G::BaseField: PrimeField,
    {
        plnms
            .iter()
            .enumerate()
            .map(|(i, (poly_or_evals, blinders))| {
                let poly = match poly_or_evals {
                    DensePolynomialOrEvaluations::DensePolynomial(poly) => (*poly).clone(),
                    DensePolynomialOrEvaluations::Evaluations(evals, _) => {
                        (*evals).clone().interpolate()
                    }
                };
                let chunked_polynomial =
                    poly.to_chunked_polynomial(blinders.elems.len(), self.g.len());
                let chunked_commitment = { self.commit_non_hiding(&poly, blinders.elems.len()) };
                let masked_commitment = match self.mask_custom(chunked_commitment, blinders) {
                    Ok(comm) => comm,
                    Err(err) => panic!("Error at index {i}: {err}"),
                };
                let chunked_evals = elm
                    .iter()
                    .map(|elm| chunked_polynomial.evaluate_chunks(*elm))
                    .collect();
                Evaluation {
                    commitment: masked_commitment.commitment,

                    evaluations: chunked_evals,
                }
            })
            .collect()
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct OpeningProof<G: AffineCurve> {
    /// vector of rounds of L & R commitments
    #[serde_as(as = "Vec<(o1_utils::serialization::SerdeAs, o1_utils::serialization::SerdeAs)>")]
    pub lr: Vec<(G, G)>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub delta: G,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z1: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z2: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub sg: G,
}

impl<
        BaseField: PrimeField,
        G: AffineCurve<BaseField = BaseField> + CommitmentCurve + EndoCurve,
    > crate::OpenProof<G> for OpeningProof<G>
{
    type SRS = SRS<G>;

    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineCurve>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: PolynomialsToCombine<G, D>,
        elm: &[<G as AffineCurve>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineCurve>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineCurve>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                       // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge:
            Clone + FqSponge<<G as AffineCurve>::BaseField, G, <G as AffineCurve>::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.open(group_map, plnms, elm, polyscale, evalscale, sponge, rng)
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
        RNG: RngCore + CryptoRng,
    {
        srs.verify(group_map, batch, rng)
    }
}

pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineCurve> OpeningProof<G> {
    pub fn prechallenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<G::ScalarField>> {
        let _t = sponge.challenge_fq();
        self.lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_prechallenge(sponge)
            })
            .collect()
    }

    pub fn challenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        endo_r: &G::ScalarField,
        sponge: &mut EFqSponge,
    ) -> Challenges<G::ScalarField> {
        let chal: Vec<_> = self
            .lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_challenge(endo_r, sponge)
            })
            .collect();

        let chal_inv = {
            let mut cs = chal.clone();
            ark_ff::batch_inversion(&mut cs);
            cs
        };

        Challenges { chal, chal_inv }
    }
}

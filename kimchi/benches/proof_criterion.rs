use ark_ff::{BigInteger256, Fp256};
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use groupmap::GroupMap;
use kimchi::{
    bench::BenchmarkCtx, circuits::constraints::ConstraintSystem, curve::KimchiCurve,
    proof::ProverProof, prover_index::ProverIndex,
};
use kimchi::{circuits::polynomial::COLUMNS, proof::RecursionChallenge};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::srs::SRS;

pub fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof creation");
    group.sample_size(10).sampling_mode(SamplingMode::Flat); // for slow benchmarks

    let ctx = BenchmarkCtx::new(1 << 10);
    group.bench_function(
        format!("proof creation (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| black_box(ctx.create_proof())),
    );

    let ctx = BenchmarkCtx::new(1 << 14);
    group.bench_function(
        format!("proof creation (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| black_box(ctx.create_proof())),
    );

    for id in 1..=4 {
        let prove = block_prover(id);
        group.bench_function(format!("block proof creation. id: {id}"), |b| {
            b.iter(|| black_box(prove()))
        });
    }

    let proof_and_public = ctx.create_proof();

    group.sample_size(100).sampling_mode(SamplingMode::Auto);
    group.bench_function(
        format!("proof verification (SRS size 2^{})", ctx.srs_size()),
        |b| b.iter(|| ctx.batch_verification(black_box(&vec![proof_and_public.clone()]))),
    );
}

const OTHER_URS_LENGTH: usize = 65536;

pub fn get_srs() -> SRS<Vesta> {
    // We need an URS with 65536 points (should be in the other verfifier index - step?)
    SRS::<Vesta>::create(OTHER_URS_LENGTH)
}

type EFqSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type EFrSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

fn block_prover(id: u64) -> impl Fn() -> ProverProof<Vesta> {
    use serde_with::serde_as;
    #[serde_as]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Inputs {
        constraint_system: ConstraintSystem<Fp>,
        #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
        witness: [Vec<Fp>; COLUMNS],
        prev_challenges: Vec<RecursionChallenge<Vesta>>,
    }

    let path = std::env::var("CRITERION_HOME").unwrap();
    let path = std::path::PathBuf::from(path);
    let filename = path
        .join("../../kimchi/resources/block_prover_inputs")
        .join(id.to_string());
    eprintln!("{}", filename.as_os_str().to_str().unwrap());
    let f = std::fs::read(dbg!(filename)).unwrap();
    let inputs: Inputs = serde_json::from_slice(&f).unwrap();

    let group_map = GroupMap::<Fq>::setup();
    let endo = inputs.constraint_system.endo;
    let mut srs = get_srs();
    srs.add_lagrange_basis(inputs.constraint_system.domain.d1);
    let index = ProverIndex::create(inputs.constraint_system, endo, srs.into());
    let witness = inputs.witness;
    let prev = inputs.prev_challenges;

    move || {
        ProverProof::create_recursive::<EFqSponge, EFrSponge>(
            &group_map,
            witness.clone(),
            &[],
            &index,
            prev.clone(),
            None,
        )
        .unwrap()
    }
}

criterion_group!(benches, bench_proof_creation);
criterion_main!(benches);

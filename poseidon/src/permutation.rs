//! The permutation module contains the function implementing the permutation used in Poseidon

use crate::constants::SpongeConstants;
use crate::poseidon::{sbox, ArithmeticSpongeParams};
use ark_ff::Field;

fn apply_mds_matrix<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &[F],
) -> [F; 3] {
    assert_eq!(params.mds.len(), 3);
    if SC::PERM_FULL_MDS {
        let mut new_state = [F::zero(); 3];
        for (i, sub_params) in params.mds.iter().enumerate() {
            for (state, param) in state.iter().zip(sub_params) {
                new_state[i].add_assign(*param * state);
            }
        }
        new_state
    } else {
        [
            state[0] + state[2],
            state[0] + state[1],
            state[1] + state[2],
        ]
    }
}

pub fn full_round<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut Vec<F>,
    r: usize,
) {
    for state_i in state.iter_mut() {
        *state_i = sbox::<F, SC>(*state_i);
    }
    let new_state = apply_mds_matrix::<F, SC>(params, state);
    state.clear();
    state.extend(new_state);
    for (i, x) in params.round_constants[r].iter().enumerate() {
        state[i].add_assign(x);
    }
}

pub fn half_rounds<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut [F],
) {
    for r in 0..SC::PERM_HALF_ROUNDS_FULL {
        for (i, x) in params.round_constants[r].iter().enumerate() {
            state[i].add_assign(x);
        }
        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }
        apply_mds_matrix::<F, SC>(params, state);
    }

    for r in 0..SC::PERM_ROUNDS_PARTIAL {
        for (i, x) in params.round_constants[SC::PERM_HALF_ROUNDS_FULL + r]
            .iter()
            .enumerate()
        {
            state[i].add_assign(x);
        }
        state[0] = sbox::<F, SC>(state[0]);
        apply_mds_matrix::<F, SC>(params, state);
    }

    for r in 0..SC::PERM_HALF_ROUNDS_FULL {
        for (i, x) in params.round_constants
            [SC::PERM_HALF_ROUNDS_FULL + SC::PERM_ROUNDS_PARTIAL + r]
            .iter()
            .enumerate()
        {
            state[i].add_assign(x);
        }
        for state_i in state.iter_mut() {
            *state_i = sbox::<F, SC>(*state_i);
        }
        apply_mds_matrix::<F, SC>(params, state);
    }
}

pub fn poseidon_block_cipher<F: Field, SC: SpongeConstants>(
    params: &ArithmeticSpongeParams<F>,
    state: &mut Vec<F>,
) {
    if SC::PERM_HALF_ROUNDS_FULL == 0 {
        if SC::PERM_INITIAL_ARK {
            for (i, x) in params.round_constants[0].iter().enumerate() {
                state[i].add_assign(x);
            }
            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<F, SC>(params, state, r + 1);
            }
        } else {
            for r in 0..SC::PERM_ROUNDS_FULL {
                full_round::<F, SC>(params, state, r);
            }
        }
    } else {
        half_rounds::<F, SC>(params, state);
    }
}

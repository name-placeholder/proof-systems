///```text
/// Foreign field multiplication circuit gates
///
/// These circuit gates are used to constrain that
///
///     left_input * right_input = quotient * foreign_modulus + remainder
///
/// For more details please see https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view
/// and apply this mapping to the variable names.
///
///     left_input0 => a0  right_input0 => b0  quotient0 => q0  remainder0 => r0
///     left_input1 => a1  right_input1 => b1  quotient1 => q1  remainder1 => r1
///     left_input2 => a2  right_input2 => b2  quotient2 => q2  remainder2 => r2
///
///     product_mid0 => p10    product_mid1_0 => p100    product_mid1_1 => p111
///     carry0       => v0     carry1_0       => v10     carry1_1       => v11
///
/// Inputs:
///   * foreign_modulus        := foreign field modulus (currently stored in constraint system)
///   * left_input $~\in F_f$  := left foreign field element multiplicand
///   * right_input $~\in F_f$ := right foreign field element multiplicand
///
///   N.b. the native field modulus is obtainable from F, the native field's trait bound below.
///
/// Witness:
///   * quotient $~\in F_f$  := foreign field quotient
///   * remainder $~\in F_f$ := foreign field remainder
///   * carry0               := two bit carry
///   * carry1_0             := low 88 bits of carry1
///   * carry1_1             := high 3 bits of carry1
///
/// Layout:
///
///   Row(s) | Gate              | Witness
///      0-3 | multi-range-check | left_input multiplicand
///      4-7 | multi-range-check | right_input multiplicand
///     8-11 | multi-range-check | quotient
///    12-15 | multi-range-check | remainder
///    16-19 | multi-range-check | product_mid0, product_mid1_0, carry1_0
///       20 | ForeignFieldMul   | (see below)
///       21 | Zero              | (see below)
///
/// The last two rows are layed out like this.
///
///             Curr                    Next
///   Columns | ForeignFieldMul       | Zero
///         0 | left_input0    (copy) | quotient1       (copy)
///         1 | left_input1    (copy) | quotient2       (copy)
///         2 | left_input2    (copy) | 2^9 * carry1_1  (plookup)
///         3 | right_input0   (copy) | 2^8 * quotient2 (plookup)
///         4 | right_input1   (copy) | remainder0      (copy)
///         5 | right_input2   (copy) | remainder1      (copy)
///         6 | quotient0      (copy) | remainder2      (copy)
///         7 | product_mid0          | (unused)
///         8 | product_mid1_0        | (unused)
///         9 | product_mid1_1        | (unused)
///        10 | carry0                | (unused)
///        11 | carry1_0              | (unused)
///        12 | carry1_1              | (unused)
///        13 | (unused)              | (unused)
///        14 | (unused)              | (unused)
///
use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, witness_next, ConstantExpr, E},
    gate::GateType,
};

/// ForeignFieldMul0
///    Rows: Curr + Next
#[derive(Default)]
pub struct ForeignFieldMul<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul);
    const CONSTRAINTS: u32 = 7;

    fn constraints() -> Vec<E<F>> {
        // Columns | Curr           | Next
        // -|-|-
        //       0 | left_input0    | quotient1
        //       1 | left_input1    | quotient2
        //       2 | left_input2    | 2^9 * carry1_1
        //       3 | right_input0   | 2^8 * quotient2
        //       4 | right_input1   | remainder0
        //       5 | right_input2   | remainder1
        //       6 | quotient0      | remainder2
        //       7 | product_mid0   | (unused)
        //       8 | product_mid1_0 | (unused)
        //       9 | product_mid1_1 | (unused)
        //      10 | carry0         | (unused)
        //      11 | carry1_0       | (unused)
        //      12 | carry1_1       | (unused)

        // Load the Curr row variables into well-named variables
        let left_input0 = witness_curr(0);
        let left_input1 = witness_curr(1);
        let left_input2 = witness_curr(2);
        let right_input0 = witness_curr(3);
        let right_input2 = witness_curr(4);
        let right_input1 = witness_curr(5);
        let quotient0 = witness_curr(6);
        let product_mid0 = witness_curr(7);
        let product_mid1_0 = witness_curr(8);
        let product_mid1_1 = witness_curr(9);
        let carry0 = witness_curr(10);
        let carry1_0 = witness_curr(11);
        let carry1_1 = witness_curr(12);

        // Load the Next row variables into well-named variables
        let quotient1 = witness_next(0);
        let quotient2 = witness_next(1);
        let carry1_1_shift = witness_next(2);
        let quotient2_shift = witness_next(3);
        let remainder0 = witness_next(4);
        let remainder1 = witness_next(5);
        let remainder2 = witness_next(6);

        let mut constraints = vec![];

        // Helpers
        let eight = E::from(8);
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(512);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = two_to_88.clone().pow(2);

        // Foreign field modulus
        let foreign_modulus0 = E::constant(ConstantExpr::ForeignFieldModulus(0));
        let foreign_modulus1 = E::constant(ConstantExpr::ForeignFieldModulus(1));
        let foreign_modulus2 = E::constant(ConstantExpr::ForeignFieldModulus(1));

        // 0) Define intermediate products for readability
        //    product_low := left_input0 * right_input0 - quotient0 * foreign_modulus0
        //    product_mid := left_input0 * right_input1 + left_input1 * right_input0
        //                   - quotient0 * foreign_modulus1 - quotient1 * foreign_modulus0
        //    product_hi := left_input0 * right_input2 + left_input2 * right_input0 + left_input1 * right_input1
        //                  - quotient0 * foreign_modulus2 - quotient2 * foreign_modulus0 - quotient1 * foreign_modulus1

        let product_low = left_input0.clone() * right_input0.clone()
            - quotient0.clone() * foreign_modulus0.clone();
        let product_mid = left_input0.clone() * right_input1.clone()
            + left_input1.clone() * right_input0.clone()
            - quotient0.clone() * foreign_modulus1.clone()
            - quotient1.clone() * foreign_modulus0.clone();
        let product_hi =
            left_input0 * right_input2 + left_input2 * right_input0 + left_input1 * right_input1
                - quotient0 * foreign_modulus2
                - quotient2.clone() * foreign_modulus0
                - quotient1 * foreign_modulus1;

        // 1) Constrain decomposition of middle intermediate product
        //    * product_mid_prefix = 2^88 * product_mid1_1 + product_mid1_0
        //    * product_mid_sum = 2^88 * p11 + product_mid0
        //    * 2^88 * product_mid_prefix + product_mid0  = product_mid
        let product_mid_prefix = two_to_88.clone() * product_mid1_1.clone() + product_mid1_0;
        let product_mid_sum = two_to_88.clone() * product_mid_prefix + product_mid0.clone();
        constraints.push(product_mid - product_mid_sum.clone());

        // 2) Constrain carry witness value `carry0` $~\in [0, 2^2)$
        constraints.push(crumb(&carry0));

        // 3) Constrain intermediate product fragment `product_mid1_1` $~\in [0, 2^2)$
        constraints.push(crumb(&product_mid1_1));

        // 4) Constrain `carry1_1` value
        constraints.push(carry1_1_shift - two_to_9 * carry1_1.clone());

        // 5) Constrain shifted `carry0` witness value to prove $u_0$'s leading bits are zero
        //    For details on $u_0$ and why this is valid, please see this design document section:
        //        https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products
        //
        //    2^176 * carry0 = product_low - remainder0 + 2^88 ( product_mid0 - remainder1)
        let low_half = product_low - remainder0 + two_to_88.clone() * (product_mid0 - remainder1);
        constraints.push(low_half - two_to_176 * carry0.clone());

        // 6) Constrain the shifted `carry1` witness value to prove $u_1$'s bits are zero
        //    For details on $u_1$ and why this is valid, please see this design document section:
        //        https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view#Intermediate-products
        //
        //    Let `carry_1` $~=~$ `carry1_0` $~+ 2^{3} *~$ `carry1_1`
        //    Check 2^88 * v1 = 2^88 * product_mid1_1 + product_mid1_0 + product_hi - remainder2 + carry0
        let carry1_sum = carry1_0 + eight * carry1_1;
        let up_half = carry0 + product_mid_sum + product_hi - remainder2;
        constraints.push(up_half - two_to_88 * carry1_sum);

        // 7) Check zero prefix of quotient2
        constraints.push(two_to_8 * quotient2 - quotient2_shift);

        // 8-9) Plookups on the Next row @ columns 2 and 3
        constraints
    }
}

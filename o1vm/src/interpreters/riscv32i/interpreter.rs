use strum_macros::{EnumCount, EnumIter};

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Hash, Ord, PartialOrd)]
pub enum Instruction {
    RType(RInstruction),
    IType(IInstruction),
    SType(SInstruction),
    BType(BInstruction),
    UType(UInstruction),
    JType(JInstruction),
}

// See
// https://www.cs.cornell.edu/courses/cs3410/2024fa/assignments/cpusim/riscv-instructions.pdf
// for the order
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum RInstruction {
    #[default]
    Add, // add
    Sub,                  // sub
    ShiftLeftLogical,     // sll
    SetLessThan,          // slt
    SetLessThanUnsigned,  // sltu
    Xor,                  // xor
    ShiftRightLogical,    // srl
    ShiftRightArithmetic, // sra
    Or,                   // or
    And,                  // and
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum IInstruction {
    #[default]
    LoadByte, // lb
    LoadHalf,         // lh
    LoadWord,         // lw
    LoadByteUnsigned, // lbu
    LoadHalfUnsigned, // lhu

    ShiftLeftLogicalImmediate,     // slli
    ShiftRightLogicalImmediate,    // srli
    ShiftRightArithmeticImmediate, // srai
    SetLessThanImmediate,          // slti
    SetLessThanImmediateUnsigned,  // sltiu

    AddImmediate, // addi
    XorImmediate, // xori
    OrImmediate,  // ori
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum SInstruction {
    #[default]
    StoreByte, // sb
    StoreHalf, // sh
    StoreWord, // sw
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum BInstruction {
    #[default]
    BranchEq, // beq
    BranchNeq,              // bne
    BranchLessThan,         // blt
    BranchGe,               // bge
    BranchLessThanUnsigned, // bltu
    BranchGreaterThanEqual, // bgeu
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum UInstruction {
    #[default]
    LoadUpperImmediate, // lui
    AddUpperImmediate, // auipc
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, EnumCount, EnumIter, Default, Hash, Ord, PartialOrd,
)]
pub enum JInstruction {
    #[default]
    JumpAndLink, // jal
    Jump, // jalr
}

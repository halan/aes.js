//! ![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/320px-AES-ShiftRows.svg.png)
//!
//! `shift_rows` é uma permutação fixa das 16 posições do estado. A versão
//! inversa é a permutação que desfaz a primeira. Expressamos ambas como
//! `permute` sobre arrays de índices — a operação fica explícita no dado.

use crate::types::Block;
use crate::utils::permute;

const SHIFT_ROWS: [usize; 16] = [
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11,
];

const SHIFT_ROWS_INV: [usize; 16] = [
     0, 13, 10,  7,
     4,  1, 14, 11,
     8,  5,  2, 15,
    12,  9,  6,  3,
];

#[must_use]
pub fn shift_rows(state: Block) -> Block {
    permute(&SHIFT_ROWS, &state)
}

#[must_use]
pub fn shift_rows_inv(state: Block) -> Block {
    permute(&SHIFT_ROWS_INV, &state)
}

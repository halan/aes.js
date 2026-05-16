//! Composição das 4 etapas em rounds completos.
//!
//! A primeira e a última rodada do AES são casos particulares — daí
//! `first_round`, `middle_round`, `last_round` (e seus inversos). Como
//! `add_round_key` é seu próprio inverso, `first_round` e `last_round_inv`
//! coincidem com ele.

pub mod add_round_key;
pub mod mix_columns;
pub mod shift_rows;
pub mod sub_bytes;

use crate::types::Block;

pub use add_round_key::add_round_key;
pub use mix_columns::{mix_columns, mix_columns_inv};
pub use shift_rows::{shift_rows, shift_rows_inv};
pub use sub_bytes::{sub_bytes, sub_bytes_inv, sub_word};

/// O primeiro round é apenas o XOR com a chave original (pré-whitening).
#[must_use]
pub fn first_round(key: &Block, state: Block) -> Block {
    add_round_key(key, state)
}

/// `middle_round`: sub → shift → mix → addKey.
#[must_use]
pub fn middle_round(key: &Block, state: Block) -> Block {
    add_round_key(key, mix_columns(shift_rows(sub_bytes(state))))
}

/// `last_round`: igual ao middle, mas sem `mix_columns`.
#[must_use]
pub fn last_round(key: &Block, state: Block) -> Block {
    add_round_key(key, shift_rows(sub_bytes(state)))
}

/// `first_round_inv` desfaz `last_round`: addKey → shiftRowsInv → subBytesInv.
#[must_use]
pub fn first_round_inv(key: &Block, state: Block) -> Block {
    sub_bytes_inv(shift_rows_inv(add_round_key(key, state)))
}

/// `middle_round_inv` desfaz `middle_round`: addKey → mixColInv → shiftRowsInv → subBytesInv.
#[must_use]
pub fn middle_round_inv(key: &Block, state: Block) -> Block {
    sub_bytes_inv(shift_rows_inv(mix_columns_inv(add_round_key(key, state))))
}

/// O último round invertido desfaz o primeiro round direto — só XOR.
#[must_use]
pub fn last_round_inv(key: &Block, state: Block) -> Block {
    add_round_key(key, state)
}

//! ![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ad/AES-AddRoundKey.svg/320px-AES-AddRoundKey.svg.png)
//!
//! `add_round_key` é apenas um XOR byte a byte. Como o XOR é involutivo,
//! a operação é seu próprio inverso — não existe `add_round_key_inv`.

use crate::types::Block;
use crate::utils::xor;

#[must_use]
pub fn add_round_key(key: &Block, state: Block) -> Block {
    xor(key, &state)
}

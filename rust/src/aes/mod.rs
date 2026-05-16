//! Núcleo AES-128 — encriptação e decriptação de um bloco.
//!
//! [`Aes128`] guarda as round keys já expandidas para que múltiplas chamadas
//! com a mesma chave não repaguem a expansão. No estilo TS, `AES.encrypt(key)`
//! e `AES.decrypt(key)` produziam funções curried; aqui o equivalente é
//! `Aes128::new(&key)` seguido de `.encrypt(state)` / `.decrypt(state)`.

pub mod expand_key;
pub mod rounds;

use crate::types::{Block, Key, RoundKeys, NUM_ROUNDS};
use expand_key::expand_key;
use rounds::{
    first_round, first_round_inv, last_round, last_round_inv, middle_round, middle_round_inv,
};

/// Cifrador AES-128 com round keys pré-computadas.
#[derive(Clone, Debug)]
pub struct Aes128 {
    round_keys: RoundKeys,
}

impl Aes128 {
    /// Cria um novo cifrador a partir de uma chave de 128 bits.
    #[must_use]
    pub fn new(key: &Key) -> Self {
        Self {
            round_keys: expand_key(key),
        }
    }

    /// Cifra um bloco. Estrutura: primeiro round (XOR com chave inicial),
    /// 9 rounds intermediários, último round (sem `mix_columns`).
    #[must_use]
    pub fn encrypt(&self, state: Block) -> Block {
        let state = first_round(&self.round_keys[0], state);
        let state = (1..NUM_ROUNDS).fold(state, |s, i| middle_round(&self.round_keys[i], s));
        last_round(&self.round_keys[NUM_ROUNDS], state)
    }

    /// Decifra um bloco. Aplica as round keys em ordem reversa e usa os
    /// rounds inversos. Não inverter explicitamente o array — iteramos
    /// pelo índice na direção oposta.
    #[must_use]
    pub fn decrypt(&self, state: Block) -> Block {
        let state = first_round_inv(&self.round_keys[NUM_ROUNDS], state);
        let state = (1..NUM_ROUNDS)
            .rev()
            .fold(state, |s, i| middle_round_inv(&self.round_keys[i], s));
        last_round_inv(&self.round_keys[0], state)
    }
}

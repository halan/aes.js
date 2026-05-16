//! Núcleo AES — encriptação e decriptação de um bloco.
//!
//! Genérico sobre o número de round keys (`NRK`): AES-128 = 11, AES-192 = 13,
//! AES-256 = 15. Type aliases [`Aes128`], [`Aes192`] e [`Aes256`] expõem cada
//! variante. As funções `encrypt`/`decrypt` são as mesmas — só o número de
//! rounds intermediários muda (`NRK - 1`).

pub mod expand_key;
pub mod rounds;

use crate::types::Block;
use rounds::{
    first_round, first_round_inv, last_round, last_round_inv, middle_round, middle_round_inv,
};

/// Cifrador AES genérico. `NRK` é a quantidade de round keys (11/13/15);
/// dele derivamos o número de rounds = `NRK - 1`.
///
/// Construtores específicos de tamanho ficam nas implementações dos type
/// aliases [`Aes128`] / [`Aes192`] / [`Aes256`] — assim cada um aceita
/// só o tamanho de chave correto, validado em compile-time.
#[derive(Clone, Debug)]
pub struct Aes<const NRK: usize> {
    round_keys: [Block; NRK],
}

impl<const NRK: usize> Aes<NRK> {
    /// Cifra um bloco. Estrutura: primeiro round (XOR com chave inicial),
    /// `NRK - 2` rounds intermediários, último round (sem `mix_columns`).
    #[must_use]
    pub fn encrypt(&self, state: Block) -> Block {
        let nr = NRK - 1;
        let state = first_round(&self.round_keys[0], state);
        let state = (1..nr).fold(state, |s, i| middle_round(&self.round_keys[i], s));
        last_round(&self.round_keys[nr], state)
    }

    /// Decifra um bloco. Round keys aplicadas em ordem reversa, com as
    /// versões inversas das etapas.
    #[must_use]
    pub fn decrypt(&self, state: Block) -> Block {
        let nr = NRK - 1;
        let state = first_round_inv(&self.round_keys[nr], state);
        let state = (1..nr)
            .rev()
            .fold(state, |s, i| middle_round_inv(&self.round_keys[i], s));
        last_round_inv(&self.round_keys[0], state)
    }
}

/// AES-128 — 10 rounds, 11 round keys, chave de 16 bytes.
pub type Aes128 = Aes<11>;

/// AES-192 — 12 rounds, 13 round keys, chave de 24 bytes.
pub type Aes192 = Aes<13>;

/// AES-256 — 14 rounds, 15 round keys, chave de 32 bytes.
pub type Aes256 = Aes<15>;

impl Aes128 {
    /// Constrói um cifrador AES-128 a partir de uma chave de 16 bytes.
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_key::expand_key::<16, 11>(key),
        }
    }
}

impl Aes192 {
    /// Constrói um cifrador AES-192 a partir de uma chave de 24 bytes.
    #[must_use]
    pub fn new(key: &[u8; 24]) -> Self {
        Self {
            round_keys: expand_key::expand_key::<24, 13>(key),
        }
    }
}

impl Aes256 {
    /// Constrói um cifrador AES-256 a partir de uma chave de 32 bytes.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            round_keys: expand_key::expand_key::<32, 15>(key),
        }
    }
}

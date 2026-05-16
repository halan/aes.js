//! Expansão de chave (Rijndael key schedule) para AES-128.
//!
//! No estilo TS, isso era um `scanl` duplo: o externo gera 10 chaves novas a
//! partir da inicial; cada chave nova é, por sua vez, um `scanl` com XOR sobre
//! as 4 words da chave anterior. Em Rust expressamos o mesmo via
//! [`Iterator::scan`], que mapeia diretamente o conceito — e ainda mantém a
//! tipagem do array de tamanho fixo (`RoundKeys = [Block; 11]`).

use crate::aes::rounds::sub_word;
use crate::types::{Block, Byte, Key, RoundKeys, Word, NUM_ROUNDS};
use crate::utils::xor;
use std::array;

/// Constantes `rcon` aplicadas no primeiro byte de cada nova chave gerada.
/// Uma para cada `NUM_ROUNDS`. `RCON[0]` não é usada (artifact da
/// especificação histórica).
/// [Detalhes](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon).
const RCON: [Byte; NUM_ROUNDS + 1] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Rotaciona os bytes de uma word: `[a, b, c, d] -> [b, c, d, a]`.
fn rot_word([a, b, c, d]: Word) -> Word {
    [b, c, d, a]
}

/// XOR no primeiro byte de uma word com `rcon`.
fn xor_first_byte(rcon: Byte, [first, b, c, d]: Word) -> Word {
    [first ^ rcon, b, c, d]
}

/// Última word de uma chave (bytes 12..16). `try_into` é infalível porque o
/// próprio tipo garante 16 bytes em `Block`.
fn last_word(key: &Block) -> Word {
    key[12..16]
        .try_into()
        .expect("Block has 16 bytes, slice 12..16 has 4")
}

/// `key_schedule(rcon, key)` produz a "semente" usada para derivar a próxima
/// chave: aplica `lastWord → rotWord → subWord → xor com rcon` na chave atual.
fn key_schedule(rcon: Byte, prev: &Block) -> Word {
    xor_first_byte(rcon, sub_word(rot_word(last_word(prev))))
}

/// Deriva a próxima chave de 128 bits. Cada word nova é o XOR da word
/// correspondente em `prev` com o resultado acumulado — `scan` em Rust
/// preserva exatamente a semântica do `scanl(xor)(initial)` da versão TS.
fn generate(initial: Word, prev: &Block) -> Block {
    let words: [Word; 4] = array::from_fn(|i| {
        prev[i * 4..i * 4 + 4]
            .try_into()
            .expect("Block has 16 bytes, slice of 4 is a Word")
    });

    let derived: Vec<Word> = words
        .iter()
        .scan(initial, |state, &w| {
            *state = xor(state, &w);
            Some(*state)
        })
        .collect();

    let mut out: Block = [0; 16];
    for (i, w) in derived.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(w);
    }
    out
}

/// Expande uma chave AES-128 em 11 round keys.
///
/// O tipo `Key = [u8; 16]` torna desnecessária a validação de comprimento
/// em runtime — o compilador rejeita chaves de outro tamanho. AES-192 e
/// AES-256 exigiriam outros tipos e outros `expand_key`.
#[must_use]
pub fn expand_key(key: &Key) -> RoundKeys {
    let derived = (1..=NUM_ROUNDS).scan(*key, |prev, i| {
        let seed = key_schedule(RCON[i], prev);
        *prev = generate(seed, prev);
        Some(*prev)
    });

    let mut keys: RoundKeys = [[0; 16]; NUM_ROUNDS + 1];
    keys[0] = *key;
    for (i, k) in derived.enumerate() {
        keys[i + 1] = k;
    }
    keys
}

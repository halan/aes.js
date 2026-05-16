//! Expansão de chave (Rijndael key schedule) — generaliza AES-128, 192 e 256.
//!
//! Os três tamanhos de chave diferem em três pontos:
//!   - Quantidade de words na chave inicial (`Nk` = 4, 6, 8)
//!   - Número de rounds (10, 12, 14) e portanto de round keys (11, 13, 15)
//!   - AES-256 aplica `sub_word` adicional sem `rot_word` a cada 4 words
//!     dentro de cada bloco de 8 (`Nk > 6 && i % Nk == 4`)
//!
//! Uma única função genérica sobre os comprimentos cobre todos os casos.
//! Const generics garantem em compile-time que `Aes128::new` só aceita chaves
//! de 16 bytes, `Aes192::new` só de 24, e `Aes256::new` só de 32.

use crate::aes::rounds::sub_word;
use crate::types::{Block, Byte, Word};
use crate::utils::xor;

/// Constantes `rcon`. Dimensionada para o pior caso (AES-128 usa até
/// índice 10; AES-192 até 8; AES-256 até 7).
/// [Detalhes](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon).
const RCON: [Byte; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

fn rot_word([a, b, c, d]: Word) -> Word {
    [b, c, d, a]
}

/// Algoritmo Rijndael generalizado. `KEY_BYTES` é o tamanho da chave em bytes
/// (16/24/32) e `ROUND_KEYS` é a quantidade total de round keys (11/13/15).
///
/// O loop principal segue FIPS-197 §5.2:
///   - A cada `Nk` words, aplicar `rot_word → sub_word → xor com rcon`
///   - Em AES-256 (`Nk > 6`), a cada 4 words intermediárias, aplicar apenas
///     `sub_word` (sem rotação, sem rcon)
///   - As demais são apenas `prev XOR temp` em cima da word `Nk` posições atrás
#[must_use]
pub fn expand_key<const KEY_BYTES: usize, const ROUND_KEYS: usize>(
    key: &[u8; KEY_BYTES],
) -> [Block; ROUND_KEYS] {
    let nk = KEY_BYTES / 4;
    let total_words = 4 * ROUND_KEYS;

    let mut words: Vec<Word> = Vec::with_capacity(total_words);

    // Primeiras `Nk` words = chave inicial.
    for i in 0..nk {
        words.push([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    for i in nk..total_words {
        let mut temp = words[i - 1];
        if i.is_multiple_of(nk) {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // AES-256 only
            temp = sub_word(temp);
        }
        words.push(xor(&words[i - nk], &temp));
    }

    // Combina as words em blocos de 16 bytes (round keys).
    let mut round_keys = [[0u8; 16]; ROUND_KEYS];
    for (rk_idx, rk) in round_keys.iter_mut().enumerate() {
        for w in 0..4 {
            let word = words[rk_idx * 4 + w];
            rk[w * 4..w * 4 + 4].copy_from_slice(&word);
        }
    }
    round_keys
}

//! Modos de operação — ECB e CBC.
//!
//! Os modos consomem qualquer [`BlockCipher`]. Em TS isso era apenas
//! `(state: Block) => Block`; aqui usamos um trait — Rust idiomático para
//! abstrair a operação sem perder o estilo funcional. [`Aes128`] implementa
//! o trait automaticamente, mas qualquer outro cifrador pode ser plugado.
//!
//! CBC encrypt é um `scanl` (cada bloco cifrado depende do anterior).
//! CBC decrypt é um `scan` onde o *estado* propagado é o bloco cifrado
//! anterior, mas a saída é o plaintext recuperado — exatamente o `mapAccumL`
//! da versão TS.
//!
//! [`Aes128`]: crate::Aes128

use crate::aes::Aes;
use crate::padding::{pksc7, pksc7_inv, PaddingError};
use crate::types::{Block, BLOCK_SIZE};
use crate::utils::xor;

/// Abstrai a operação por bloco. O trait permite que os modos sejam
/// genéricos sobre o cifrador concreto — a única dependência são as funções
/// `encrypt` e `decrypt` sobre [`Block`]. AES-128, 192 e 256 implementam
/// via uma única impl genérica sobre `NRK` (número de round keys).
pub trait BlockCipher {
    fn encrypt(&self, state: Block) -> Block;
    fn decrypt(&self, state: Block) -> Block;
}

impl<const NRK: usize> BlockCipher for Aes<NRK> {
    fn encrypt(&self, state: Block) -> Block {
        Aes::<NRK>::encrypt(self, state)
    }
    fn decrypt(&self, state: Block) -> Block {
        Aes::<NRK>::decrypt(self, state)
    }
}

/// Converte um chunk de slice (`&[u8]` de tamanho 16) para um [`Block`].
/// Infalível porque os iteradores de chunks usados aqui garantem o tamanho.
fn to_block(chunk: &[u8]) -> Block {
    chunk.try_into().expect("chunks_exact(16) yields 16 bytes")
}

// ## CBC
//
// AVISO: o IV deve ser **único e imprevisível** para cada chamada com a mesma
// chave. Reutilizar IV vaza igualdade entre prefixos de plaintext; IV
// previsível habilita ataques de plaintext escolhido. CBC sozinho não
// autentica — combine com um MAC ou prefira um modo AEAD (GCM).

#[must_use]
pub fn cbc_encrypt<C: BlockCipher + ?Sized>(cipher: &C, iv: &Block, plaintext: &[u8]) -> Vec<u8> {
    let padded = pksc7(plaintext);

    padded
        .chunks_exact(BLOCK_SIZE)
        .map(to_block)
        .scan(*iv, |prev, block| {
            let c = cipher.encrypt(xor(prev, &block));
            *prev = c;
            Some(c)
        })
        .flatten()
        .collect()
}

/// # Errors
///
/// Propaga [`PaddingError`] se o plaintext resultante tiver padding PKCS#7
/// inválido (tipicamente um sinal de tampering ou chave/IV errados).
pub fn cbc_decrypt<C: BlockCipher + ?Sized>(
    cipher: &C,
    iv: &Block,
    ciphertext: &[u8],
) -> Result<Vec<u8>, PaddingError> {
    let plain: Vec<u8> = ciphertext
        .chunks_exact(BLOCK_SIZE)
        .map(to_block)
        .scan(*iv, |prev, block| {
            let plain = xor(prev, &cipher.decrypt(block));
            *prev = block;
            Some(plain)
        })
        .flatten()
        .collect();

    pksc7_inv(&plain)
}

// ## ECB
//
// AVISO: ECB é determinístico e expõe padrões — blocos plaintext idênticos
// produzem ciphertext idêntico. Implementado apenas para fins didáticos.

#[must_use]
pub fn ecb_encrypt<C: BlockCipher + ?Sized>(cipher: &C, plaintext: &[u8]) -> Vec<u8> {
    pksc7(plaintext)
        .chunks_exact(BLOCK_SIZE)
        .map(to_block)
        .flat_map(|b| cipher.encrypt(b))
        .collect()
}

/// # Errors
///
/// Propaga [`PaddingError`] se o plaintext resultante tiver padding PKCS#7
/// inválido.
pub fn ecb_decrypt<C: BlockCipher + ?Sized>(
    cipher: &C,
    ciphertext: &[u8],
) -> Result<Vec<u8>, PaddingError> {
    let plain: Vec<u8> = ciphertext
        .chunks_exact(BLOCK_SIZE)
        .map(to_block)
        .flat_map(|b| cipher.decrypt(b))
        .collect();

    pksc7_inv(&plain)
}

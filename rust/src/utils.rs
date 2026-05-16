//! Combinadores genéricos sobre arrays de tamanho fixo.
//!
//! `const N: usize` substitui aqui o que em TS exigia `BlockLike` + validação
//! de comprimento em runtime. Se você tentar `xor(&block, &word)` o compilador
//! rejeita — não há equivalente em runtime do `Error: mismatched lengths`.

use crate::types::Byte;
use std::array;

/// XOR byte a byte. Operação 1-para-1 sobre arrays do mesmo tamanho;
/// `const N` torna a igualdade de tamanhos uma garantia de tipo.
#[must_use]
pub fn xor<const N: usize>(a: &[Byte; N], b: &[Byte; N]) -> [Byte; N] {
    array::from_fn(|i| a[i] ^ b[i])
}

/// Permutação fixa: `permute(&indices, &arr)[j] == arr[indices[j]]`.
/// Usado por `shift_rows` para expressar a operação como dado em vez de código.
#[must_use]
pub fn permute<const N: usize>(indices: &[usize; N], arr: &[Byte; N]) -> [Byte; N] {
    array::from_fn(|i| arr[indices[i]])
}

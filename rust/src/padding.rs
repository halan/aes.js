//! Padding PKCS#7 com validação.
//!
//! PKCS#7 completa o último bloco com bytes cujo *valor* é o número de bytes
//! adicionados. Quando o input já está alinhado, adiciona-se um bloco inteiro
//! — assim a recuperação fica sempre inequívoca.
//!
//! `pksc7_inv` devolve `Result<Vec<u8>, PaddingError>`: a versão TS lançava
//! exceção, aqui o erro fica explícito no tipo. Sem validação, esta função
//! abriria a porta para padding oracle attacks quando combinada com CBC sem
//! MAC.

use crate::types::BLOCK_SIZE;

/// Erro de validação PKCS#7. Não distinguimos as variantes externamente — em
/// CBC, qualquer leak entre "tamanho fora do intervalo" e "bytes inconsistentes"
/// pode virar oráculo. Para fins didáticos, listamos como variantes internas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingError {
    Empty,
    SizeOutOfRange,
    InconsistentBytes,
}

impl std::fmt::Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid PKCS#7 padding")
    }
}

impl std::error::Error for PaddingError {}

/// Aplica padding PKCS#7 ao input, alinhando-o a múltiplos de [`BLOCK_SIZE`].
///
/// # Panics
///
/// Nunca, na prática — `pad_len` está em `[1, BLOCK_SIZE]`, sempre cabe em `u8`.
#[must_use]
pub fn pksc7(input: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - input.len() % BLOCK_SIZE;
    // `pad_len` está em `[1, BLOCK_SIZE]` — quando o input já é alinhado,
    // adicionamos um bloco completo. Truncamento para `u8` é seguro porque
    // `BLOCK_SIZE = 16 < 256`.
    let pad_byte = u8::try_from(pad_len).expect("pad_len ≤ BLOCK_SIZE = 16");

    let mut out = Vec::with_capacity(input.len() + pad_len);
    out.extend_from_slice(input);
    out.extend(std::iter::repeat_n(pad_byte, pad_len));
    out
}

/// Remove o padding PKCS#7, falhando explicitamente em qualquer anomalia.
///
/// # Errors
///
/// Retorna [`PaddingError`] se a entrada estiver vazia, se o último byte
/// estiver fora do intervalo `[1, 16]`, ou se algum dos `size` últimos bytes
/// não for igual a `size`.
///
/// # Panics
///
/// Nunca, na prática — o `expect` interno após `len > 0` é uma asserção
/// para o leitor humano, não um panic acessível.
pub fn pksc7_inv(input: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let len = input.len();
    if len == 0 {
        return Err(PaddingError::Empty);
    }

    let size = *input.last().expect("len > 0 verified above") as usize;

    if !(1..=BLOCK_SIZE).contains(&size) || size > len {
        return Err(PaddingError::SizeOutOfRange);
    }

    if !input[len - size..].iter().all(|&b| b as usize == size) {
        return Err(PaddingError::InconsistentBytes);
    }

    Ok(input[..len - size].to_vec())
}

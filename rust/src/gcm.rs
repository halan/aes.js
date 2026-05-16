//! AES-GCM — modo AEAD com autenticação.
//!
//! Fecha o gap do report de segurança: ciphertext não-maleável via tag de
//! 128 bits. CTR mode dá confidencialidade; GHASH dá autenticidade.
//!
//! Referência: [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final).
//!
//! API espelha o lado TS: `gcm_encrypt` devolve `(ciphertext, tag)`,
//! `gcm_decrypt` valida o tag em tempo constante antes de devolver o
//! plaintext.

use crate::op_modes::BlockCipher;
use crate::types::Block;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcmAuthError;

impl std::fmt::Display for GcmAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GCM authentication failed")
    }
}

impl std::error::Error for GcmAuthError {}

/// Resultado da cifração GCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcmCiphertext {
    pub ciphertext: Vec<u8>,
    pub tag: Block,
}

// ### GHASH — multiplicação em GF(2^128)
//
// Polinômio de redução: `x^128 + x^7 + x^2 + x + 1`. Em GCM a representação
// é refletida — o coeficiente de `x^0` fica no bit mais significativo do
// byte 0, e o de `x^127` fica no bit menos significativo do byte 15. Daí o
// loop iterar do MSB ao LSB de `x` e o "shift right" propagar o bit menos
// significativo de cada byte ao mais significativo do byte seguinte.
fn gmul(x: &Block, y: &Block) -> Block {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - i % 8)) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        let carry = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if carry == 1 {
            v[0] ^= 0xe1;
        }
    }

    z
}

fn ghash(h: &Block, data: &[u8]) -> Block {
    let mut y = [0u8; 16];
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for j in 0..16 {
            y[j] ^= block[j];
        }
        y = gmul(&y, h);
    }
    y
}

// ### CTR mode
//
// Apenas os 32 bits finais do contador são incrementados; os 96 primeiros
// (o nonce) permanecem fixos. Wraparound em 2^32 → keystream se repete, o
// que é catastrófico. GCM limita o plaintext a ~64 GiB por esse motivo.
fn inc32(counter: &mut Block) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            return;
        }
    }
}

fn gctr<C: BlockCipher + ?Sized>(cipher: &C, initial_counter: Block, data: &[u8]) -> Vec<u8> {
    let mut counter = initial_counter;
    let mut out = Vec::with_capacity(data.len());

    for chunk in data.chunks(16) {
        let ks = cipher.encrypt(counter);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        inc32(&mut counter);
    }
    out
}

// ### J_0
//
// Para IV de 96 bits, J_0 = IV || 0^31 || 1. Caso geral, J_0 vem de um
// GHASH sobre o próprio IV. O caso comum é o caminho rápido.
fn compute_j0(h: &Block, iv: &[u8]) -> Block {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        return j0;
    }

    let mut padded = iv.to_vec();
    while !padded.len().is_multiple_of(16) {
        padded.push(0);
    }
    padded.extend_from_slice(&[0u8; 8]);
    let bit_len = (iv.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_be_bytes());
    ghash(h, &padded)
}

fn compute_s(h: &Block, aad: &[u8], ct: &[u8]) -> Block {
    let v = (16 - aad.len() % 16) % 16;
    let u = (16 - ct.len() % 16) % 16;
    let mut buf = Vec::with_capacity(aad.len() + v + ct.len() + u + 16);
    buf.extend_from_slice(aad);
    buf.resize(buf.len() + v, 0);
    buf.extend_from_slice(ct);
    buf.resize(buf.len() + u, 0);
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ct.len() as u64).wrapping_mul(8);
    buf.extend_from_slice(&aad_bits.to_be_bytes());
    buf.extend_from_slice(&ct_bits.to_be_bytes());
    ghash(h, &buf)
}

/// Comparação byte-a-byte em tempo constante. Sem curto-circuito — vazaria
/// timing sobre quais bytes batem, oráculo suficiente para forjar tags.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Cifra `plaintext` com AES-GCM. IV de 96 bits é o caso recomendado.
///
/// **O IV precisa ser único por (chave, mensagem).** Reusar IV com a mesma
/// chave colapsa a segurança do GCM por completo.
#[must_use]
pub fn gcm_encrypt<C: BlockCipher + ?Sized>(
    cipher: &C,
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> GcmCiphertext {
    let h = cipher.encrypt([0; 16]);
    let j0 = compute_j0(&h, iv);

    let mut counter = j0;
    inc32(&mut counter);
    let ciphertext = gctr(cipher, counter, plaintext);

    let s = compute_s(&h, aad, &ciphertext);
    let tag_bytes = gctr(cipher, j0, &s);
    let mut tag: Block = [0; 16];
    tag.copy_from_slice(&tag_bytes);

    GcmCiphertext { ciphertext, tag }
}

/// Decifra GCM validando o tag. O tag é verificado **antes** de qualquer
/// plaintext ser devolvido.
///
/// # Errors
///
/// [`GcmAuthError`] se o tag não bate — sinal de tampering, chave/IV
/// errados, ou AAD divergente.
pub fn gcm_decrypt<C: BlockCipher + ?Sized>(
    cipher: &C,
    iv: &[u8],
    ciphertext: &[u8],
    tag: &Block,
    aad: &[u8],
) -> Result<Vec<u8>, GcmAuthError> {
    let h = cipher.encrypt([0; 16]);
    let j0 = compute_j0(&h, iv);

    let s = compute_s(&h, aad, ciphertext);
    let expected_tag = gctr(cipher, j0, &s);

    if !ct_eq(&expected_tag, tag) {
        return Err(GcmAuthError);
    }

    let mut counter = j0;
    inc32(&mut counter);
    Ok(gctr(cipher, counter, ciphertext))
}

//! # AES-128 didático em Rust
//!
//! Porta da implementação em TypeScript (ver `../src`). O propósito é o mesmo:
//! mostrar o algoritmo com clareza, não competir em performance ou em
//! resistência a ataques de canal lateral. Aqui aproveitamos o sistema de
//! tipos do Rust — arrays de tamanho fixo, generics constantes, `Result` para
//! erros de validação — para deixar invariantes que em TS eram convenção
//! viraram garantias do compilador.
//!
//! Estrutura paralela ao lado TS:
//! - [`aes`] — núcleo do cifrador (rounds, key schedule)
//! - [`op_modes`] — modos de operação (ECB, CBC)
//! - [`padding`] — PKCS#7 com validação
//! - [`utils`] — combinadores (xor, permute)
//!
//! Não usar em produção. Sem MAC, sem proteção contra cache timing.

pub mod aes;
pub mod gcm;
pub mod op_modes;
pub mod padding;
pub mod types;
pub mod utils;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use aes::{Aes, Aes128, Aes192, Aes256};
pub use gcm::{gcm_decrypt, gcm_encrypt, GcmAuthError, GcmCiphertext};
pub use op_modes::{cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt, BlockCipher};
pub use padding::PaddingError;
pub use types::{Block, Byte, Key, RoundKeys, Word};

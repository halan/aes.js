//! Tipos fundamentais. Aliases sobre arrays de tamanho fixo — o compilador
//! garante as cardinalidades que em TS eram convenção verificada em runtime.
//!
//! `Block`, `Word` e `Key` são `Copy`: o pipeline pode passá-los por valor sem
//! `Clone` explícito, mantendo o estilo funcional sem alocações intermediárias.

/// Um byte. Alias para legibilidade — o intervalo `[0, 255]` é garantido pelo
/// próprio `u8`, não exige documentação.
pub type Byte = u8;

/// Word AES = 4 bytes. Unidade básica do key schedule.
pub type Word = [Byte; 4];

/// Block AES = 16 bytes. Estado interno e unidade de cifragem.
pub type Block = [Byte; 16];

/// Chave AES-128. O tipo deixa explícito que só essa variante é suportada;
/// AES-192 e AES-256 exigiriam outros aliases e um `expand_key` separado.
pub type Key = Block;

/// 11 round keys: a chave original mais 10 derivadas pelo key schedule.
pub type RoundKeys = [Block; 11];

pub const BLOCK_SIZE: usize = 16;
pub const WORD_SIZE: usize = 4;
pub const NUM_ROUNDS: usize = 10; // AES-128

//! Bindings WebAssembly via `wasm-bindgen`.
//!
//! Expõe AES-128/192/256 e os modos CBC, ECB e GCM para consumo a partir de
//! JS/TS. A construção é a mesma do lado nativo — passamos por
//! `wasm-bindgen` apenas para que `Uint8Array` do JS se converta
//! automaticamente em `&[u8]` (e vice-versa para `Vec<u8>` na saída).
//!
//! Compile com `wasm-pack build --target nodejs -- --features wasm` ou
//! `--target web` para o navegador.

use wasm_bindgen::prelude::*;

use crate::{
    cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
    op_modes::BlockCipher,
    Aes128, Aes192, Aes256,
};

/// Cifrador AES com tamanho de chave decidido em runtime. JS não tem o
/// equivalente das nossas type aliases `Aes128`/`Aes192`/`Aes256`, então
/// determinamos a variante pelo comprimento da chave passada ao construtor.
#[wasm_bindgen]
pub struct AesCipher {
    inner: Variant,
}

enum Variant {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl BlockCipher for Variant {
    fn encrypt(&self, state: [u8; 16]) -> [u8; 16] {
        match self {
            Self::Aes128(c) => c.encrypt(state),
            Self::Aes192(c) => c.encrypt(state),
            Self::Aes256(c) => c.encrypt(state),
        }
    }
    fn decrypt(&self, state: [u8; 16]) -> [u8; 16] {
        match self {
            Self::Aes128(c) => c.decrypt(state),
            Self::Aes192(c) => c.decrypt(state),
            Self::Aes256(c) => c.decrypt(state),
        }
    }
}

#[wasm_bindgen]
impl AesCipher {
    /// Constrói um cifrador a partir da chave. Aceita 16, 24 ou 32 bytes —
    /// qualquer outro tamanho lança erro.
    ///
    /// # Errors
    ///
    /// Devolve um erro se `key.len()` não for 16, 24 ou 32.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<AesCipher, JsError> {
        let inner = match key.len() {
            16 => Variant::Aes128(Aes128::new(key.try_into().unwrap())),
            24 => Variant::Aes192(Aes192::new(key.try_into().unwrap())),
            32 => Variant::Aes256(Aes256::new(key.try_into().unwrap())),
            n => return Err(JsError::new(&format!("AES key must be 16, 24 or 32 bytes, got {n}"))),
        };
        Ok(AesCipher { inner })
    }

    /// Cifra um bloco de exatamente 16 bytes.
    ///
    /// # Errors
    ///
    /// `block.len() != 16`.
    #[wasm_bindgen(js_name = encryptBlock)]
    pub fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, JsError> {
        let b: [u8; 16] = block
            .try_into()
            .map_err(|_| JsError::new("Block must be 16 bytes"))?;
        Ok(self.inner.encrypt(b).to_vec())
    }

    /// Decifra um bloco de exatamente 16 bytes.
    ///
    /// # Errors
    ///
    /// `block.len() != 16`.
    #[wasm_bindgen(js_name = decryptBlock)]
    pub fn decrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, JsError> {
        let b: [u8; 16] = block
            .try_into()
            .map_err(|_| JsError::new("Block must be 16 bytes"))?;
        Ok(self.inner.decrypt(b).to_vec())
    }

    /// CBC encrypt com IV de 16 bytes.
    ///
    /// # Errors
    ///
    /// `iv.len() != 16`.
    #[wasm_bindgen(js_name = cbcEncrypt)]
    pub fn cbc_encrypt(&self, iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| JsError::new("IV must be 16 bytes"))?;
        Ok(cbc_encrypt(&self.inner, &iv, plaintext))
    }

    /// CBC decrypt; valida PKCS#7 e propaga erro.
    ///
    /// # Errors
    ///
    /// IV não tem 16 bytes, ou o padding PKCS#7 está inválido (tampering,
    /// chave/IV errados).
    #[wasm_bindgen(js_name = cbcDecrypt)]
    pub fn cbc_decrypt(&self, iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| JsError::new("IV must be 16 bytes"))?;
        cbc_decrypt(&self.inner, &iv, ciphertext).map_err(|e| JsError::new(&e.to_string()))
    }

    /// ECB encrypt — apenas didático, **não usar em produção**.
    #[wasm_bindgen(js_name = ecbEncrypt)]
    pub fn ecb_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        ecb_encrypt(&self.inner, plaintext)
    }

    /// # Errors
    ///
    /// Padding PKCS#7 inválido.
    #[wasm_bindgen(js_name = ecbDecrypt)]
    pub fn ecb_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        ecb_decrypt(&self.inner, ciphertext).map_err(|e| JsError::new(&e.to_string()))
    }

    /// GCM encrypt. Devolve `ciphertext || tag` (tag de 16 bytes apensado).
    /// Convenção comum em APIs de cripto. O lado JS deve separar os últimos
    /// 16 bytes para validar autenticidade.
    #[wasm_bindgen(js_name = gcmEncrypt)]
    pub fn gcm_encrypt(&self, iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let result = gcm_encrypt(&self.inner, iv, plaintext, aad);
        let mut out = result.ciphertext;
        out.extend_from_slice(&result.tag);
        out
    }

    /// GCM decrypt. Espera `ciphertext_with_tag` no formato produzido por
    /// `gcm_encrypt` (últimos 16 bytes = tag).
    ///
    /// # Errors
    ///
    /// Entrada com menos de 16 bytes, ou autenticação falhou.
    #[wasm_bindgen(js_name = gcmDecrypt)]
    pub fn gcm_decrypt(
        &self,
        iv: &[u8],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if ciphertext_with_tag.len() < 16 {
            return Err(JsError::new("GCM input must include 16-byte tag"));
        }
        let split = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..split];
        let tag: [u8; 16] = ciphertext_with_tag[split..]
            .try_into()
            .expect("split ensures 16 bytes remain");
        gcm_decrypt(&self.inner, iv, ciphertext, &tag, aad)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

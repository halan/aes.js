// Testes que cruzam as duas implementações: o lado TS de `src/` e o WASM
// produzido a partir de `rust/`. Mesmo input deve produzir mesmo output.
//
// Pré-requisito: `npm run build:wasm` (gera `rust/pkg-node/`). Quando o
// artefato não está presente, os testes são pulados via `before` — assim o
// `npm test` ainda passa em ambientes sem Rust/wasm-pack instalado.

import { expect } from 'chai'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import { encrypt, decrypt } from '#aes'
import { cbc, cbcInv, ecb, ecbInv } from '#opModes'
import { gcmEncrypt, gcmDecrypt } from '#gcm'

const __dirname = dirname(fileURLToPath(import.meta.url))
const wasmPath = resolve(__dirname, '..', 'rust', 'pkg-node', 'aes_rs.js')
const wasmAvailable = existsSync(wasmPath)

type AesCipherCtor = new (key: Uint8Array) => {
  encryptBlock(block: Uint8Array): Uint8Array
  decryptBlock(block: Uint8Array): Uint8Array
  cbcEncrypt(iv: Uint8Array, plaintext: Uint8Array): Uint8Array
  cbcDecrypt(iv: Uint8Array, ciphertext: Uint8Array): Uint8Array
  ecbEncrypt(plaintext: Uint8Array): Uint8Array
  ecbDecrypt(ciphertext: Uint8Array): Uint8Array
  gcmEncrypt(iv: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array
  gcmDecrypt(iv: Uint8Array, ciphertextWithTag: Uint8Array, aad: Uint8Array): Uint8Array
}

const conditionalSuite = wasmAvailable ? describe : describe.skip

conditionalSuite('WASM bridge — TS and Rust agree on outputs', function () {
  let AesCipher: AesCipherCtor

  before(async function () {
    const mod = await import(wasmPath) as { AesCipher: AesCipherCtor }
    AesCipher = mod.AesCipher
  })

  const key = Buffer.from('0f1571c947d9e8590cb7add6af7f6798', 'hex')
  const iv  = Buffer.from('53616c7465645f5f7aadee8bc39c0e65', 'hex')

  it('block encrypt: TS and WASM produce identical ciphertext', () => {
    const plain = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
    const tsOut = encrypt(key)(plain)
    const wasmOut = Buffer.from(new AesCipher(key).encryptBlock(plain))
    expect(tsOut).to.deep.equal(wasmOut)
  })

  it('block decrypt: TS and WASM are inverses of each other', () => {
    const plain = Buffer.from('Hola mundo!!!!!!')
    const ct = encrypt(key)(plain)
    const recovered = Buffer.from(new AesCipher(key).decryptBlock(ct))
    expect(recovered).to.deep.equal(plain)
  })

  it('CBC: WASM result decrypts back via TS', () => {
    const plain = Buffer.from('isto deve sobreviver a um round-trip cruzado')
    const ct = Buffer.from(new AesCipher(key).cbcEncrypt(iv, plain))
    const recovered = cbcInv(decrypt(key))(iv)(ct)
    expect(recovered.toString('utf8')).to.equal(plain.toString('utf8'))
  })

  it('CBC: TS result decrypts back via WASM', () => {
    const plain = Buffer.from('e vice-versa')
    const ct = cbc(encrypt(key))(iv)(plain)
    const recovered = Buffer.from(new AesCipher(key).cbcDecrypt(iv, ct))
    expect(recovered.toString('utf8')).to.equal(plain.toString('utf8'))
  })

  it('ECB: WASM and TS round-trip cross over', () => {
    const plain = Buffer.from('ECB cross check', 'utf8')
    const ctWasm = Buffer.from(new AesCipher(key).ecbEncrypt(plain))
    const ctTs   = ecb(encrypt(key))(plain)
    expect(ctWasm).to.deep.equal(ctTs)

    const back = ecbInv(decrypt(key))(ctWasm)
    expect(back.toString('utf8')).to.equal(plain.toString('utf8'))
  })

  it('GCM: WASM result authenticates and decrypts via TS', () => {
    const gcmIv = iv.subarray(0, 12)
    const plain = Buffer.from('AEAD message with proper authentication')
    const aad   = Buffer.from('header')

    const cipher = new AesCipher(key)
    const combined = Buffer.from(cipher.gcmEncrypt(gcmIv, plain, aad))
    // WASM concatena tag (16 bytes) ao final do ciphertext
    const ct  = combined.subarray(0, -16)
    const tag = combined.subarray(-16)

    const recovered = gcmDecrypt(encrypt(key), gcmIv, ct, tag, aad)
    expect(recovered.toString('utf8')).to.equal(plain.toString('utf8'))
  })

  it('GCM: TS result authenticates and decrypts via WASM', () => {
    const gcmIv = iv.subarray(0, 12)
    const plain = Buffer.from('and back the other way')
    const aad   = Buffer.from('header')

    const { ciphertext, tag } = gcmEncrypt(encrypt(key), gcmIv, plain, aad)
    const combined = Buffer.concat([ciphertext, tag])
    const recovered = Buffer.from(new AesCipher(key).gcmDecrypt(gcmIv, combined, aad))
    expect(recovered.toString('utf8')).to.equal(plain.toString('utf8'))
  })
})

if (!wasmAvailable) {
  describe('WASM bridge', () => {
    it('(skipped — run `npm run build:wasm` to enable)', function () {
      this.skip()
    })
  })
}

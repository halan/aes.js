// ## AES-GCM — modo AEAD com autenticação
//
// GCM = AES em modo CTR + GHASH como MAC, combinados num único pipeline.
// Diferente de CBC, é autenticado: o `tag` retornado funciona como MAC e a
// decifração só devolve plaintext se o tag bater (`GcmAuthError` caso
// contrário). Esta é a peça que faltava ao report de segurança — fecha o
// gap "ciphertext maleável" do CBC sem MAC.
//
// Não usa padding: o tamanho do ciphertext é exatamente o do plaintext.
//
// Referência: [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final).

import type { Block, BlockLike, Byte, ByteInput } from './types.ts'

// `EncryptFn` casa com a assinatura curried de `AES.encrypt(key)` — GCM só
// usa a função de cifragem (CTR mode é simétrico: decifrar = cifrar de novo).
type EncryptFn = (block: BlockLike) => Buffer

// ### GHASH — multiplicação em GF(2^128)
//
// O corpo é GF(2)[x] / (x^128 + x^7 + x^2 + x + 1). GCM usa a representação
// "refletida": o bit mais significativo do polinômio fica no índice 0. Daí o
// loop iterar do bit MSB ao LSB de `x`, e o `shift right` propagar o bit
// menos significativo de cada byte ao mais significativo do byte seguinte.
const gmul = (x: Block, y: Block): Block => {
  const z = new Uint8Array(16)
  const v = new Uint8Array(y)

  for (let i = 0; i < 128; i++) {
    const bit = (x[i >> 3]! >> (7 - (i & 7))) & 1
    if (bit) {
      for (let j = 0; j < 16; j++) z[j]! ^= v[j]!
    }

    const carry = v[15]! & 1
    for (let j = 15; j > 0; j--) {
      v[j] = (v[j]! >> 1) | ((v[j - 1]! & 1) << 7)
    }
    v[0] = v[0]! >> 1

    if (carry) v[0] ^= 0xe1
  }

  return Array.from(z)
}

// `ghash(h, data)` processa `data` em blocos de 16 bytes, mantendo um
// acumulador `y` que a cada iteração vira `(y XOR bloco) * h`. Equivalente
// a um `reduce` sobre os blocos com a operação composta.
const ghash = (h: Block, data: readonly Byte[]): Block => {
  let y: Byte[] = new Array<Byte>(16).fill(0)
  for (let i = 0; i < data.length; i += 16) {
    const xored: Byte[] = new Array<Byte>(16).fill(0)
    for (let j = 0; j < 16 && i + j < data.length; j++) {
      xored[j] = (y[j] ?? 0) ^ (data[i + j] ?? 0)
    }
    y = gmul(xored, h) as Byte[]
  }
  return y
}

// ### CTR mode
//
// Incrementa apenas os 32 bits finais do contador (big-endian). Os primeiros
// 96 bits — o nonce — permanecem fixos. O incremento em `inc32` envelopa em
// 2^32 (depois disso o keystream se repete, o que é catastrófico). GCM
// limita o plaintext a (2^39 - 256) bits = ~64 GiB exatamente por isso.
const inc32 = (counter: Byte[]): void => {
  for (let i = 15; i >= 12; i--) {
    counter[i] = (counter[i]! + 1) & 0xff
    if (counter[i] !== 0) return
  }
}

const gctr = (encrypt: EncryptFn, initialCounter: Block, data: readonly Byte[]): Byte[] => {
  const result: Byte[] = []
  const counter: Byte[] = [...initialCounter]

  for (let i = 0; i < data.length; i += 16) {
    const keystream = encrypt(counter)
    for (let j = 0; j < 16 && i + j < data.length; j++) {
      result.push(data[i + j]! ^ keystream[j]!)
    }
    inc32(counter)
  }
  return result
}

// ### J_0 — bloco inicial de contador
//
// Para o caso comum (IV de 96 bits), J_0 = IV || 0^31 || 1.
// Para outros tamanhos, J_0 vem de um GHASH sobre o próprio IV — caminho mais
// caro e raramente usado, mas implementado por completude.
const computeJ0 = (h: Block, iv: readonly Byte[]): Block => {
  if (iv.length === 12) {
    return [...iv, 0, 0, 0, 1] as unknown as Block
  }
  const padded: Byte[] = [...iv]
  while (padded.length % 16 !== 0) padded.push(0)
  // Append 8 zero bytes + 8 bytes de bit-length do IV (big-endian, 64 bits).
  for (let i = 0; i < 8; i++) padded.push(0)
  padded.push(...lengthBytes64BE(iv.length))
  return ghash(h, padded)
}

// 64-bit big-endian do bit-length. JS Number suporta inteiros até 2^53,
// suficiente para qualquer input prático; dividimos em halves de 32 bits
// para evitar perda de precisão em operadores bitwise.
const lengthBytes64BE = (byteLen: number): Byte[] => {
  const bitLen = byteLen * 8
  const high = Math.floor(bitLen / 0x100000000)
  const low = bitLen >>> 0
  return [
    (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff,
  ]
}

// Comparação byte-a-byte em tempo constante. `===` curto-circuitaria,
// vazando timing sobre quais bytes batem — em GCM, isso seria oráculo
// suficiente para forjar tags (basta busca byte-a-byte).
const constantTimeEq = (a: readonly Byte[], b: readonly Byte[]): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!
  }
  return diff === 0
}

// ### S — bloco de autenticação
//
// `S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)`.
// `v` e `u` são paddings de zero para alinhar A e C a blocos de 16 bytes.
const computeS = (h: Block, aad: readonly Byte[], ciphertext: readonly Byte[]): Block => {
  const v = (16 - (aad.length % 16)) % 16
  const u = (16 - (ciphertext.length % 16)) % 16
  return ghash(h, [
    ...aad,
    ...new Array<Byte>(v).fill(0),
    ...ciphertext,
    ...new Array<Byte>(u).fill(0),
    ...lengthBytes64BE(aad.length),
    ...lengthBytes64BE(ciphertext.length),
  ])
}

const toBytes = (input: ByteInput): Byte[] => {
  if (typeof input === 'string') return [...Buffer.from(input)]
  if (input instanceof Uint8Array) return [...input]
  return [...input]
}

export interface GcmResult {
  ciphertext: Buffer
  tag: Buffer
}

export class GcmAuthError extends Error {
  constructor() {
    super('GCM authentication failed')
    this.name = 'GcmAuthError'
  }
}

/**
 * Cifra `plaintext` com AES-GCM. Devolve ciphertext + tag de 16 bytes.
 *
 * O IV de 96 bits é o caso recomendado e mais rápido. Tamanhos diferentes
 * são suportados, mas exigem um GHASH extra para derivar J_0.
 *
 * Pré-requisito: **o IV precisa ser único por (chave, plaintext)** — reusar
 * IV com a mesma chave colapsa a segurança do GCM (XOR de keystreams).
 */
export const gcmEncrypt = (
  encrypt: EncryptFn,
  iv: BlockLike,
  plaintext: ByteInput,
  aad: BlockLike = new Uint8Array(0),
): GcmResult => {
  const ivBytes = toBytes(iv as ByteInput)
  const ptBytes = toBytes(plaintext)
  const aadBytes = toBytes(aad as ByteInput)

  const zeroBlock: Block = new Array<Byte>(16).fill(0)
  const h: Block = [...encrypt(zeroBlock)]

  const j0 = computeJ0(h, ivBytes)

  const counterForData: Byte[] = [...j0]
  inc32(counterForData)
  const ciphertext = gctr(encrypt, counterForData as unknown as Block, ptBytes)

  const s = computeS(h, aadBytes, ciphertext)
  const tag = gctr(encrypt, j0, s)

  return {
    ciphertext: Buffer.from(ciphertext),
    tag: Buffer.from(tag),
  }
}

/**
 * Decifra GCM, validando o tag antes de devolver plaintext.
 *
 * @throws {GcmAuthError} se o tag não bate. Sem branches sensíveis a timing
 *   na comparação, então o erro vaza só "tag inválido", nunca "tag bateu
 *   nos primeiros N bytes".
 */
export const gcmDecrypt = (
  encrypt: EncryptFn,
  iv: BlockLike,
  ciphertext: BlockLike,
  tag: BlockLike,
  aad: BlockLike = new Uint8Array(0),
): Buffer => {
  const ivBytes = toBytes(iv as ByteInput)
  const ctBytes = toBytes(ciphertext as ByteInput)
  const tagBytes = toBytes(tag as ByteInput)
  const aadBytes = toBytes(aad as ByteInput)

  const zeroBlock: Block = new Array<Byte>(16).fill(0)
  const h: Block = [...encrypt(zeroBlock)]

  const j0 = computeJ0(h, ivBytes)

  // Validar autenticidade ANTES de devolver qualquer plaintext.
  const s = computeS(h, aadBytes, ctBytes)
  const expectedTag = gctr(encrypt, j0, s)
  if (!constantTimeEq(expectedTag, tagBytes)) {
    throw new GcmAuthError()
  }

  const counterForData: Byte[] = [...j0]
  inc32(counterForData)
  const plaintext = gctr(encrypt, counterForData as unknown as Block, ctBytes)

  return Buffer.from(plaintext)
}

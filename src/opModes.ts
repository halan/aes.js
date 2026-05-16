// ## Modos de operação

import { scanl, mapAccumL, flat, xor, partition, pipe, map } from './utils.ts'
import { pksc7, pksc7Inv } from './padding.ts'
import type { Block, BlockLike, ByteInput } from './types.ts'

// Os modos consomem uma função de cifração por bloco — tipicamente
// `AES.encrypt(key)` ou `AES.decrypt(key)`, que aceitam `BlockLike` e
// devolvem `Buffer`.
type BlockCipher = (state: BlockLike) => Buffer

// ### CBC
//
// O IV deve ser **único e imprevisível** para cada chamada com a mesma chave.
// Reutilizar IV vaza igualdade entre prefixos de plaintext; IV previsível
// habilita ataques de plaintext escolhido. Em produção, gerar o IV com
// `crypto.randomBytes(16)`. CBC sozinho também não autentica — combine com um
// MAC (encrypt-then-MAC) ou prefira um modo AEAD (GCM).
//
// A cifração CBC é um `scanl` puro: cada bloco cifrado depende do anterior.
// Convertemos `Buffer → Block` (`Array.from`) na entrada para uniformizar o
// pipeline em `Byte[]`; o resultado da cifração de bloco é também coagido a
// `Block` para alimentar a próxima iteração via `xor`.
export const cbc = (encrypt: BlockCipher) => (iv: BlockLike) =>
  (plaintext: ByteInput): Buffer =>
    pipe(
      pksc7(16),
      (buf: Buffer): Block[] => partition(16)<number>(Array.from(buf)),
      scanl<Block, Block>(
        (prev) => (block) => Array.from(encrypt(xor(prev)(block)))
      )(Array.from(iv)),
      flat,
      (bytes: number[]) => Buffer.from(bytes),
    )(plaintext)

// A decifração CBC é um `mapAccumL`: o estado a propagar é o bloco *cifrado*
// anterior (não o decifrado), e a saída de cada passo é o plaintext do bloco.
export const cbcInv = (decrypt: BlockCipher) => (iv: BlockLike) =>
  (ciphertext: BlockLike): Buffer =>
    pipe(
      (ct: BlockLike): Block[] => partition(16)<number>(Array.from(ct)),
      mapAccumL<Block, Block, Block>(
        (prev) => (block) => [block, xor(prev)(Array.from(decrypt(block)))]
      )(Array.from(iv)),
      flat,
      pksc7Inv,
      (buf: Buffer) => Buffer.from(buf),
    )(ciphertext)

// ### ECB
//
// AVISO: ECB é determinístico e expõe padrões — blocos plaintext idênticos
// produzem ciphertext idêntico. Exportado apenas para fins didáticos; **não
// usar em produção**.
export const ecb = (encrypt: BlockCipher) =>
  (plaintext: ByteInput): Buffer =>
    pipe(
      pksc7(16),
      (buf: Buffer): Block[] => partition(16)<number>(Array.from(buf)),
      map((block: Block): Block => Array.from(encrypt(block))),
      flat,
      (bytes: number[]) => Buffer.from(bytes),
    )(plaintext)

export const ecbInv = (decrypt: BlockCipher) =>
  (ciphertext: BlockLike): Buffer =>
    pipe(
      (ct: BlockLike): Block[] => partition(16)<number>(Array.from(ct)),
      map((block: Block): Block => Array.from(decrypt(block))),
      flat,
      pksc7Inv,
      (buf: Buffer) => Buffer.from(buf),
    )(ciphertext)

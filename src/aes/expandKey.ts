// ## Expansão das chaves

import { subBytes } from './rounds/subBytes.ts'
import { xor, pipe, map, flat, lastWord, scanl, splitInWords } from '../utils.ts'
import type { Block, Byte, Key, RoundKeys, Word } from '../types.ts'

// Constante `rcon` para xor com o primeiro byte de cada word (1 word = 4 bytes).
// Uma `rcon` por nova chave criada — 10 no total. `rcon[0]` não é utilizado.
// [Mais detalhes](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon).
const RCON: readonly Byte[] = [
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

// Rotaciona os bytes de uma word: `[a, b, c, d] -> [b, c, d, a]`.
const rotWord = ([first, ...rest]: Word): Byte[] => [...rest, first as Byte]

// `subWord` é o mesmo `subBytes`: substituição byte a byte aplicada a 4 bytes.
const subWord = subBytes

// XOR no primeiro byte de uma word com o `rcon` da rodada.
const xorFirstByte = (value: Byte) => ([first, ...rest]: Word): Byte[] =>
  [value ^ (first as Byte), ...rest]

type KeyScheduleStep = (key: Block) => Word

// `keySchedule(rcon)` aplica a sequência `lastWord → rotWord → subWord → xor com rcon`,
// produzindo a "semente" usada para gerar a próxima chave.
const keySchedule = (rcon: Byte): KeyScheduleStep =>
  pipe(
    lastWord<Byte>,
    rotWord,
    subWord,
    xorFirstByte(rcon)
  )

// `generate(initial)(key)` constrói uma nova chave de 128 bits a partir de
// uma word inicial e da chave anterior. Cada word nova é o XOR da word
// correspondente com o resultado acumulado — um `scanl` puro.
const generate = (initial: Word) => (key: Block): Block =>
  pipe(
    splitInWords<Byte>,
    scanl<Word, Word>(xor as (s: Word) => (w: Word) => Word)(initial),
    flat
  )(key)

// Esta implementação suporta apenas AES-128: chaves de outro tamanho
// produziriam uma expansão silenciosamente incorreta sem a validação.
//
// A expansão inteira é também um `scanl`: cada chave seguinte deriva da
// anterior aplicando `generate(keySchedule(rcon)(prevKey))(prevKey)`. O
// resultado final é a lista [chave original, ...10 derivadas].
const expandKey = (key: Key): RoundKeys => {
  if (key.length !== 16) {
    throw new Error(`AES-128 requires a 16-byte key, got ${key.length}`)
  }

  // Coerção única no boundary — daqui pra dentro `k` é `Byte[]`.
  const k: Block = Array.from(key)

  const derived = scanl<Block, KeyScheduleStep>(
    (prev) => (kscRcon) => generate(kscRcon(prev))(prev)
  )(k)(
    map(keySchedule)(RCON.slice(1))
  )

  return [k, ...derived].map((bytes) => Buffer.from(bytes)) as unknown as RoundKeys
}

export default expandKey

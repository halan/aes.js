// ## Rounds — composições das 4 etapas
//
// A primeira e a última rodada do AES são casos particulares, daí os nomes
// `firstRound`, `middleRound`, `lastRound` (e suas versões inversas para a
// decriptação). Lembre que `addRoundKey` é seu próprio inverso (XOR é
// involutivo), portanto não há `addRoundKeyInv`.

import { pipe } from '../../utils.ts'
import type { Block } from '../../types.ts'

import { subBytes, subBytesInv } from './subBytes.ts'
import { shiftRows, shiftRowsInv } from './shiftRows.ts'
import { mixColumns, mixColumnsInv } from './mixColumns.ts'
import { addRoundKey } from './addRoundKey.ts'

type Round = (key: Block) => (state: Block) => Block

// ### Encriptação
//
// `middleRound` aplica todas as 4 etapas. `lastRound` é igual mas sem
// `mixColumns`. `firstRound` é apenas `addRoundKey` (pré-whitening), por isso
// re-exportado como alias mais abaixo.
const middleRound: Round = (key) =>
  pipe(subBytes, shiftRows, mixColumns, addRoundKey(key))

const lastRound: Round = (key) =>
  pipe(subBytes, shiftRows, addRoundKey(key))

// ### Decriptação
//
// Cada etapa invertida na ordem oposta. `firstRoundInv` desfaz `lastRound`
// (sem `mixColumnsInv`); `lastRoundInv` desfaz `firstRound` (apenas XOR).
const firstRoundInv: Round = (key) =>
  pipe(addRoundKey(key), shiftRowsInv, subBytesInv)

const middleRoundInv: Round = (key) =>
  pipe(addRoundKey(key), mixColumnsInv, shiftRowsInv, subBytesInv)

export {
  subBytes, subBytesInv,
  shiftRows, shiftRowsInv,
  mixColumns, mixColumnsInv,
  addRoundKey,

  addRoundKey as firstRound,
  middleRound,
  lastRound,

  firstRoundInv,
  middleRoundInv,
  addRoundKey as lastRoundInv,
}

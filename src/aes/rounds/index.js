// ## Rounds — composições das 4 etapas
//
// A primeira e a última rodada do AES são casos particulares, daí os nomes
// `firstRound`, `middleRound`, `lastRound` (e suas versões inversas para a
// decriptação). Lembre que `addRoundKey` é seu próprio inverso (XOR é
// involutivo), portanto não há `addRoundKeyInv`.

import { pipe } from '../../utils.js'

import { subBytes, subBytesInv } from './subBytes.js'
import { shiftRows, shiftRowsInv } from './shiftRows.js'
import { mixColumns, mixColumnsInv } from './mixColumns.js'
import { addRoundKey } from './addRoundKey.js'

// ### Encriptação
//
// O `middleRound` aplica todas as 4 etapas. O `lastRound` é igual mas sem
// `mixColumns`. O `firstRound` é apenas `addRoundKey` (pré-whitening), por isso
// re-exportado como alias mais abaixo.
const middleRound = key =>
  pipe(subBytes, shiftRows, mixColumns, addRoundKey(key))

const lastRound = key =>
  pipe(subBytes, shiftRows, addRoundKey(key))

// ### Decriptação
//
// Cada etapa invertida na ordem oposta. O `firstRoundInv` desfaz o `lastRound`
// (sem `mixColumnsInv`); o `lastRoundInv` desfaz o `firstRound` (apenas XOR).
const firstRoundInv = key =>
  pipe(addRoundKey(key), shiftRowsInv, subBytesInv)

const middleRoundInv = key =>
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

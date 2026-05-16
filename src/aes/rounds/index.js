// ## Resumo

// Aqui basicamente eu organizei as etapas de encriptação.
// A primeira e a última rodada são diferentes das demais, assim,
// criei `firstRound`, `middleRound` e `lastRound`.
// E também suas versões invertidas para decriptação.

import { pipe } from '../../utils.js'

// São 4 as etapas de encriptação (e seus inversos!)
import { subBytes, subBytesInv } from './subBytes.js'
import { shiftRows, shiftRowsInv } from './shiftRows.js'
import { mixColumns, mixColumnsInv } from './mixColumns.js'
// Lembrando: `addRoundKey` é *comutativa*, portanto não há versão invertida dela.
import { addRoundKey } from './addRoundKey.js'

// ## Rounds de encriptação

// Os demais rounds, exceto o último, o `addRoundKey` é aplicado sobre
// um pipe de `mixColumns( shiftRows( subBytes ))`.
const middleRound = key =>
  pipe(
    subBytes,
    shiftRows,
    mixColumns,
    addRoundKey(key)
  )

// O último round não utiliza a etapa `mixColumns`
const lastRound = key =>
 pipe(
    subBytes,
    shiftRows,
    // aqui não tem mixColumns :)
    addRoundKey(key),
 )

// ## Rounds de decriptação

// As composições a seguir utilizam as versões invertidas das operações.
// Além disso são aplicados em ordem inversa cada round em si e o último round passa a ser análogo ao primeiro.
const firstRoundInv = key =>
  pipe(
    addRoundKey(key),
    // aqui não tem mixColumnsInv
    shiftRowsInv,
    subBytesInv
  )

const middleRoundInv = key =>
  pipe(
    addRoundKey(key),
    mixColumnsInv,
    shiftRowsInv,
    subBytesInv
  )


export {
  // Funções para encriptação
  subBytes,
  shiftRows,
  mixColumns,
  addRoundKey,
  // Funções para decriptação. São as mesmas de encriptação em suas formas invertidas.
  // O `addRoundKey` não tem forma invertida, pois é uma função *comutativa*
  mixColumnsInv,
  subBytesInv,
  shiftRowsInv,

  // No primeiro round da encriptação é utilizado apenas o `addRoundKey`
  addRoundKey as firstRound,
  middleRound,
  lastRound,

  // No último round da encriptação é utilizado apenas o `addRoundKey`
  firstRoundInv,
  middleRoundInv,
  addRoundKey as lastRoundInv
}

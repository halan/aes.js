// ## Resumo

// Aqui basicamente eu organizei as etapas de encriptação.
// A primeira e a última rodada são diferentes das demais, assim,
// criei `firstRound`, `middleRound` e `lastRound`.
// E também suas versões invertidas para decriptação.

import { compose } from '../utils'

// São 4 as etapas de encriptação (e seus inversos!)
import subBytes, { subBytesInv } from './subBytes'
import shiftRows, { shiftRowsInv } from './shiftRows'
import mixColumns, { mixColumnsInv } from './mixColumns'
// Lembrando: `addRoundKey` é *comutativa*, portanto não há versão invertida dela.
import addRoundKey from './addRoundKey'

// Funções para encriptação
export { subBytes, shiftRows, mixColumns, addRoundKey }
// Funções para decriptação. São as mesmas de encriptação em suas formas invertidas.
// O `addRoundKey` não tem forma invertida, pois é uma função *comutativa*
export { mixColumnsInv, subBytesInv, shiftRowsInv }

// ## Rounds de encriptação

// O primeiro round é utilizado apenas o `addRoundKey`
export const firstRound = addRoundKey

// Os demais rounds, exceto o último, o `addRoundKey` é aplicado sobre
// um pipe de `mixColumns( shiftRows( subBytes ))`.
export const middleRound = (buffer, key) =>
  addRoundKey(
    compose(mixColumns, shiftRows, subBytes)(buffer),
    key
  )

// O último round não utiliza a etapa `mixColumns`
export const lastRound = (buffer, key) =>
  addRoundKey(
    compose(shiftRows, subBytes)(buffer),
    key
  )

// ## Rounds de decriptação

// As composições a seguir utilizam as versões invertidas das operações.
// Além disso são aplicados em ordem inversa cada round em si e o último round passa a ser análogo ao primeiro.
// Assim, como na encriptação o primeiro round é apenas um `addRoundKey`,
// o último round da decriptação passa a ser o `addRoundKey` sozinho.
export const firstRoundInv = (buffer, key) =>
  compose(subBytesInv, shiftRowsInv)(addRoundKey(buffer, key))

export const middleRoundInv = (buffer, key) =>
  compose(subBytesInv, shiftRowsInv, mixColumnsInv)(addRoundKey(buffer, key))

export const lastRoundInv = addRoundKey

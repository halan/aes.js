// ## Resumo

// Aqui basicamente eu organizei as etapas de encriptação.
// A primeira e a última rodada são diferentes das demais, assim,
// criei `firstRound`, `middleRound` e `lastRound`.
// E também suas versões invertidas para decriptação.

const { compose } = require('../utils')

// São 4 as etapas de encriptação (e seus inversos!)
const { subBytes, subBytesInv } = require('./subBytes')
const { shiftRows, shiftRowsInv } = require('./shiftRows')
const { mixColumns, mixColumnsInv } = require('./mixColumns')
// Lembrando: `addRoundKey` é *comutativa*, portanto não há versão invertida dela.
const { addRoundKey } = require('./addRoundKey')

// ## Rounds de encriptação

// Os demais rounds, exceto o último, o `addRoundKey` é aplicado sobre
// um pipe de `mixColumns( shiftRows( subBytes ))`.
const middleRound = (buffer, key) =>
  addRoundKey(
    compose(mixColumns, shiftRows, subBytes)(buffer),
    key
  )

// O último round não utiliza a etapa `mixColumns`
const lastRound = (buffer, key) =>
  addRoundKey(
    compose(shiftRows, subBytes)(buffer),
    key
  )

// ## Rounds de decriptação

// As composições a seguir utilizam as versões invertidas das operações.
// Além disso são aplicados em ordem inversa cada round em si e o último round passa a ser análogo ao primeiro.
const firstRoundInv = (buffer, key) =>
  compose(subBytesInv, shiftRowsInv)(addRoundKey(buffer, key))

const middleRoundInv = (buffer, key) =>
  compose(subBytesInv, shiftRowsInv, mixColumnsInv)(addRoundKey(buffer, key))


module.exports = {
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

  // O primeiro round da encriptação é utilizado apenas o `addRoundKey`
  firstRound: addRoundKey,
  middleRound,
  lastRound,

  // O último round da encriptação é utilizado apenas o `addRoundKey`
  firstRoundInv,
  middleRoundInv,
  lastRoundInv: addRoundKey
}

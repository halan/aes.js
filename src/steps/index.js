// Aqui basicamente eu organizei as etapas de encriptação.
// A primeira e a última rodada são diferentes das demais, assim,
// criei `firstRound`, `middleRound` e `lastRound`.

import { compose } from '../utils'

// São 4 as etapas de encriptação
import subBytes from './subBytes'
import shiftRows from './shiftRows'
import mixColumns from './mixColumns'
import addRoundKey from './addRoundKey'

export { subBytes, shiftRows, mixColumns, addRoundKey }

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


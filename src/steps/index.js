import { compose } from '../utils'

import subBytes from './subBytes'
import shiftRows from './shiftRows'
import mixColumns from './mixColumns'
import addRoundKey from './addRoundKey'

export { subBytes, shiftRows, mixColumns, addRoundKey }

export const firstRound = addRoundKey

export const middleRound = (buffer, key) =>
  addRoundKey(
    compose(mixColumns, shiftRows, subBytes)(buffer),
    key
  )

export const lastRound = (buffer, key) =>
  addRoundKey(
    compose(shiftRows, subBytes)(buffer),
    key
  )


import {
  chainBlocks,
  chainBlocksInv,
  flat,
  xor,
  partition,
  pipe,
  map
} from './utils.js'
import { pksc7, pksc7Inv } from './padding.js'

const cbc = (encrypt, iv) =>
  pipe(
    pksc7(16),
    partition(16),
    chainBlocks(x =>
      pipe(
        xor(x),
        encrypt
      )
    )(iv),
    flat,
    Buffer.from
  )

const cbcInv = (decrypt, iv) =>
  pipe(
    partition(16),
    chainBlocksInv(x =>
      pipe(
        decrypt,
        xor(x)
      )
    )(iv),
    flat,
    pksc7Inv,
    Buffer.from
  )

const ecb = encrypt =>
  pipe(
    pksc7(16),
    inBlocks(16),
    map(encrypt),
    flat,
    Buffer.from
  )

const ecbInv = decrypt =>
  pipe(
    inBlocks(16),
    map(encrypt),
    flat,
    pksc7Inv,
    Buffer.from
  )

export {
  cbc,
  cbcInv,
  ecb,
  ecbInv
}

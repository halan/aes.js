// ## Padding PKCS#7

import type { Byte } from './types.ts'

const BLOCK_SIZE = 16

export const pksc7 = (target: number) => (input: Uint8Array | string | readonly Byte[]): Buffer => {
  const buf = Buffer.from(input as Parameters<typeof Buffer.from>[0])
  const padLength = target - (buf.length % target) || target
  return Buffer.concat([buf, Buffer.alloc(padLength, padLength)])
}

// Sem validação, `pksc7Inv` aceitaria padding arbitrário e abriria a porta
// para padding oracle attacks quando combinado com CBC sem MAC. Validamos
// que o tamanho está no intervalo permitido e que os `size` últimos bytes
// realmente valem `size`.
export const pksc7Inv = (input: Uint8Array | readonly Byte[]): Buffer => {
  const buf = Buffer.from(input as Parameters<typeof Buffer.from>[0])
  const len = buf.length
  const size = buf[len - 1]

  const invalid =
    len === 0 ||
    size === undefined ||
    size < 1 ||
    size > BLOCK_SIZE ||
    size > len ||
    !buf.slice(len - size).every((b) => b === size)

  if (invalid) throw new Error('Invalid PKCS#7 padding')

  return buf.slice(0, -(size as number))
}

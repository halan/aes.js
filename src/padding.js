
const pksc7 = target => input => {
  const inputBuffer = Buffer.from(input)
  const padLength = (target - inputBuffer.length % target || target)

  return Buffer.from([
    ...inputBuffer,
    ...Buffer.from(Array(padLength).fill(padLength))
  ])
}

// Bloco máximo suportado pelo AES (16 bytes). PKCS#7 válido sempre tem
// `size` no intervalo [1, blockSize] e os `size` últimos bytes iguais a `size`.
// Sem essa checagem, o algoritmo aceitaria padding arbitrário — abrindo a porta
// para padding oracle attacks quando combinado com CBC sem MAC.
const BLOCK_SIZE = 16

const pksc7Inv = input => {
  const buf = Buffer.from(input)
  const len = buf.length
  const size = buf[len - 1]

  if (len === 0 || size < 1 || size > BLOCK_SIZE || size > len) {
    throw new Error('Invalid PKCS#7 padding')
  }

  for (let i = len - size; i < len; i++) {
    if (buf[i] !== size) throw new Error('Invalid PKCS#7 padding')
  }

  return buf.slice(0, -size)
}

export { pksc7, pksc7Inv }

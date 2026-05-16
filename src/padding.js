// ## Padding PKCS#7
//
// PKCS#7 completa o último bloco com bytes cujo *valor* é o número de bytes
// adicionados. Quando o input já está alinhado, adiciona-se um bloco inteiro
// — assim a recuperação do plaintext fica sempre inequívoca.

const BLOCK_SIZE = 16

const pksc7 = target => input => {
  const buf = Buffer.from(input)
  const padLength = target - buf.length % target || target
  return Buffer.concat([buf, Buffer.alloc(padLength, padLength)])
}

// Sem validação, `pksc7Inv` aceitaria padding arbitrário e abriria a porta
// para padding oracle attacks quando combinado com CBC sem MAC. Validamos
// que o tamanho está no intervalo permitido e que os `size` últimos bytes
// realmente valem `size`.
const pksc7Inv = input => {
  const buf = Buffer.from(input)
  const len = buf.length
  const size = buf[len - 1]

  const invalid =
    len === 0 ||
    size < 1 ||
    size > BLOCK_SIZE ||
    size > len ||
    !buf.slice(len - size).every(b => b === size)

  if (invalid) throw new Error('Invalid PKCS#7 padding')

  return buf.slice(0, -size)
}

export { pksc7, pksc7Inv }

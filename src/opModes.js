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

// CBC requer que o IV seja **único e imprevisível** para cada chamada com a
// mesma chave. Reutilizar IV vaza a igualdade entre prefixos de plaintext;
// IV previsível habilita ataques de plaintext escolhido. Em produção, sempre
// gerar o IV com `crypto.randomBytes(16)` (Node) ou equivalente. CBC sozinho
// também não autentica — combine com um MAC ou prefira um modo AEAD (GCM).
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

// AVISO: ECB é determinístico e expõe padrões — blocos plaintext idênticos
// produzem ciphertext idêntico. Exportado apenas para fins didáticos; **não
// usar em produção**. Para qualquer caso real, prefira CBC com MAC ou GCM.
const ecb = encrypt =>
  pipe(
    pksc7(16),
    partition(16),
    map(encrypt),
    flat,
    Buffer.from
  )

const ecbInv = decrypt =>
  pipe(
    partition(16),
    map(decrypt),
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

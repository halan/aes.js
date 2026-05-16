import { scanl, mapAccumL, flat, xor, partition, pipe, map } from './utils.js'
import { pksc7, pksc7Inv } from './padding.js'

// ## CBC
//
// O IV deve ser **único e imprevisível** para cada chamada com a mesma chave.
// Reutilizar IV vaza a igualdade entre prefixos de plaintext; IV previsível
// habilita ataques de plaintext escolhido. Em produção, gerar o IV com
// `crypto.randomBytes(16)`. CBC sozinho também não autentica — combine com um
// MAC (encrypt-then-MAC) ou prefira um modo AEAD (GCM).
//
// A cifração CBC é um `scanl` puro: cada bloco cifrado depende do anterior.
const cbc = encrypt => iv =>
  pipe(
    pksc7(16),
    partition(16),
    scanl(prev => block => encrypt(xor(prev)(block)))(iv),
    flat,
    Buffer.from
  )

// A decifração CBC é um `mapAccumL`: o estado a propagar é o bloco *cifrado*
// anterior (não o decifrado), e a saída de cada passo é o plaintext do bloco.
const cbcInv = decrypt => iv =>
  pipe(
    partition(16),
    mapAccumL(prev => block => [block, xor(prev)(decrypt(block))])(iv),
    flat,
    pksc7Inv,
    Buffer.from
  )

// ## ECB
//
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

export { cbc, cbcInv, ecb, ecbInv }

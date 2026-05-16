// ## Expansão das chaves

import { subBytes } from './rounds/subBytes.js'

import {
  xor, pipe, map, flat, lastWord, scanl, splitInWords
} from '../utils.js'

// ### Constante Rcon

// Constante rcon para ser feito xor com o primeiro byte de cada word (1 word = 4 bytes).
// Uma `rcon` para cada nova chave criada — ou seja, 10. `rcon[0]` não é utilizado.
// [Mais detalhes](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon).
const RCON =
  [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

// ### `KeyScheduleCore`

// Rotaciona os bytes de uma word: `[0, 1, 2, 3] -> [1, 2, 3, 0]`.
const rotWord = ([first, ...rest]) => [...rest, first]

// `subWord` é o mesmo `subBytes`. A operação é byte-a-byte; aplicar a 4
// ou a 16 bytes é exatamente o mesmo procedimento.
const subWord = subBytes

// XOR no primeiro byte de uma word com o `rcon` da rodada.
const xorFirstByte = value => ([first, ...rest]) =>
  [value ^ first, ...rest]

// Aplica a sequência `lastWord → rotWord → subWord → xor com rcon`,
// produzindo a "semente" usada para gerar a próxima chave.
const keySchedule = rcon =>
  pipe(lastWord, rotWord, subWord, xorFirstByte(rcon))


// ### Geração das chaves

// `generate(initial)(key)` constrói uma nova chave de 128 bits a partir de
// uma word inicial e da chave anterior. A nova chave é o resultado de um
// `scanl` com `xor` sobre as 4 words da chave anterior: cada word nova é o
// XOR da word correspondente com o resultado acumulado.
const generate = initial =>
  pipe(
    splitInWords,
    scanl(xor)(initial),
    flat
  )

// ### Expansão completa

// Esta implementação suporta apenas AES-128: chaves de outro tamanho
// produziriam uma expansão silenciosamente incorreta sem a validação.
//
// A expansão inteira é também um `scanl`: a chave seguinte deriva da anterior
// aplicando `generate(keySchedule(rcon)(prevKey))(prevKey)`. O resultado final
// é a lista [chave original, ...10 derivadas].
export default key => {
  if (key.length !== 16) {
    throw new Error(`AES-128 requires a 16-byte key, got ${key.length}`)
  }

  const derived = scanl(
    prev => kscRcon => generate(kscRcon(prev))(prev)
  )(key)(
    map(keySchedule)(RCON.slice(1))
  )

  return map(Buffer.from)([key, ...derived])
}

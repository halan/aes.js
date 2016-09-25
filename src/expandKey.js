// ## Expansão das chaves

// ### Importações

// Importa o passo subBytes que faz a substituição com a S-Box
import subBytes from './steps/subBytes'

// Importa xor, que recebe duas arrays de números e aplica um xor em cada elemento correspondente.
import { xor, lastWord, splitInWords } from './utils'

// ### Constante Rcon

// Constante rcon pra ser feito xor com o primeiro byte e cada word (1 word são 4 bytes)
// 1 RCON para cada nova chave criada, ou seja: 10 rcons.
const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

// ### KeyScheduleCore

// Esta função rotaciona os bytes de um word, ex:
// `[0, 1, 2, 3] -> [1, 2, 3, 0]`
const rotWord = ([first, ...rest]) => [...rest, first]

// subWord é a mesma coisa que o subBytes. No caso da expansão de chave esse procedimento é feito
// sobre uma word. Todo o procedimento de expansão de chave é baseado em words, que funcionam como
// subblocos. Entretanto o subBytes é apenas uma substituição de um byte por outro, se aplico em 4 bytes
// ou em 16 o procedimento em si não é alterado.
const subWord = subBytes

// Faz um xor no primeiro byte de uma word com rcon especificado.
// Esse procedimento é feito exatamente 16 vezes, um para cada valor de rcon.
const xorFirstByte = ([first, ...rest], value) => [ value ^ first, ...rest ]

// Procedimento principal da expansão de chave. Aqui aplicamos a sequência:
// `rotWord`, `subWord` e por fim o `xor` no `rcon` correspondente da rodada.
// Esse procedimento é aplicado sempre na primeira word de cada chave, ou seja
// é aplicada tantas vezes iguais ao número de rodadas, que no noso caso são 11.
const keyScheduleCore = (word, rcon) => xorFirstByte(subWord(rotWord(word)), rcon)

// [Mais detalhes...](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Common_operations)

// ### Geração das chaves

// Separei nessa função, o procedimento de criar uma chave completa de 128 bits
// a partir de uma chave anterior e um valor de rcon.
const generate = (key, rcon) => {
  // Primeiramente calculo o valor base usando KeyScheduleCore que vai receber a última word da chave.
  const base = keyScheduleCore(lastWord(key), rcon)
  // divido a chave em grupos formando 4 words.
  const words = splitInWords(key)

  // Então faço um reduce em cima dessas words, ou seja, um loop de 4 iterações.
  return words.reduce( (k, word) => (
    // Em cada iteração ele monta mais uma word da chave
    // A primeira word é um xor com a primeira word da chave anterior e o valor base
    // As words seguintes é um xor com a word correspondente na chave anterior
    // e a última word calculado da própria chave (estou usando `Uint8Array` pra armazenar os valores)
    new Uint8Array([...k, ...xor(word, k.length ? lastWord(k) : base )])
  ), [])
}

// Finalmente a função de expansão de chave. Ela recebe uma chave e entrega 11!
export default key => (
  // Passo um reduce sobre os RCONS, epara cada RCON executo a função de geração de chave
  // passando como entrada a última chave e o rcon da rodada
  RCON.reduce( (keys, rcon) => {
    // Pega a última chave
    const [last] = [...keys].reverse()

    // A cada rodada, gera uma nova chave e adiciona à lista de chaves
    return [...keys, generate(last, rcon)]

  // A chave original é entregue para o reducer como uma `Uint8Array`
  }, [new Uint8Array(key)] )
)

// ## Expansão das chaves

// ### Importações

// Importa o passo `subBytes` que faz a substituição com a S-Box
const { subBytes } = require('./steps/subBytes')

// Importa xor, que recebe duas arrays de números e aplica um xor em cada elemento correspondente.
const { toUint8, xor, reverse, pipe, map, reduce, flat, lastWord, chainBlocks, splitInWords } = require('./utils')

// ### Constante Rcon

// Constante rcon para ser feito xor com o primeiro byte e cada word (1 word são 4 bytes)
// 1 rcon para cada nova chave criada, ou seja: 10 rcons.
// Mais detalhes sobre o cálculo para chegar nessa constante pode ser encontrado
// [aqui](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon).
// O rcon[0] não é utilizado no AES.
const RCON =
  [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

// ### `KeyScheduleCore`

// Esta função rotaciona os bytes de um word, ex:
// `[0, 1, 2, 3] -> [1, 2, 3, 0]`
const rotWord = ([first, ...rest]) =>
  [...rest, first]

// `subWord` é a mesma coisa que o `subBytes`. No caso da expansão de chave esse procedimento é feito
// sobre uma word. Todo o procedimento de expansão de chave é baseado em words, que funcionam como
//
// subblocos. Entretanto o `subBytes` é apenas uma substituição de um byte por outro, se aplico em 4 bytes
// ou em 16 o procedimento em si não é alterado.
const subWord = subBytes

// Faz um xor no primeiro byte de uma word com rcon especificado.
// Esse procedimento é feito exatamente 16 vezes, um para cada valor de rcon.
const xorFirstByte = value => ([first, ...rest]) =>
  [ value ^ first, ...rest ]

// Primeiramente calculo o valor base usando `KeyScheduleCore` que vai receber a última word da chave.
// Procedimento principal da expansão de chave. Aqui aplicamos a sequência:
// `rotWord`, `subWord` e por fim o `xor` no `rcon` correspondente da rodada.
// Esse procedimento é aplicado sempre na primeira word de cada chave, ou seja
// é aplicada tantas vezes iguais ao número de rodadas, que no noso caso são 11.
const keySchedule = rcon =>
  pipe(
    lastWord,
    rotWord,
    subWord,
    xorFirstByte(rcon)
  )
// [Mais detalhes...](https://en.wikipedia.org/wiki/Rijndael_key_schedule#Common_operations)

// ### Geração das chaves

// Separei nessa função, o procedimento de criar uma chave completa de 128 bits
// a partir de uma chave anterior e um valor de rcon.
const generate = (initial, key) =>
  // Divido a chave em grupos formando 4 words.
  // Então faço um reduce em cima dessas words, ou seja, um loop de 4 iterações.
  // Em cada iteração ele monta mais uma word da chave
  // A primeira word é um xor com a primeira word da chave anterior e o valor base
  // As words seguintes é um xor com a word correspondente na chave anterior
  // e a última word calculado da própria chave (estou usando `Uint8Array` pra armazenar os valores)
  pipe(
    splitInWords,
    // O chainBlocks aplicará um xor entre initial e o primeiro valor do array de words
    // O resultado passará por um xor com o segundo valor e assim por diante
    chainBlocks(xor)(initial),
    // O flat irá desfazer o splitInWords, ao invés de ter 4 elementos com 4 bytes cada, teremos 16 bytes
    flat
  )(key)


// Finalmente a função de expansão de chave. Ela recebe uma chave e entrega 11!
module.exports = key =>
  // Passo um reduce sobre os RCONS, e para cada RCON executo a função de geração de chave
  // passando como entrada a última chave e o rcon da rodada.
  pipe(
    // Prepara uma coleção de keySchedule já com rcon correspondente aplicado
    map(keySchedule),
    // Passa um chainBlocks sobre o keySchedule já cm o rcon correspondente aplicado,
    chainBlocks(keyScheduleRcon => k =>
      //e então utiiza este valor como sendo o initial da função de geração de chaves
      generate(keyScheduleRcon(k), k)
    )(key),
    // A chave inicial precisa estar contida na lista final
    keys => [key, ...keys],
    // Cada chave será transformada em `Uint8Array`
    map(toUint8)
  // O rcon[0] não é utilizado, por isso o `slice`.
  )(RCON.slice(1))


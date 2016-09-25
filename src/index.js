// ## Resumo

// O objetivo desse arquivo é bem simples.
// Organizar em alto nível a lógica básica do AES:
//   - Expandir a chave de 128 bits em 11 chaves do mesmo tamanho
//   - Executar as etapas da primeira rodada com a chave original
//   - Executar 9 vezes as etapas de embaralhalamento com as respectivas chaves
//   - Executar a rodada final com a última das 11 chaves

// [Descrição detalhada](https://pt.wikipedia.org/wiki/Advanced_Encryption_Standard#Descri.C3.A7.C3.A3o_de_Cifra)

// ### Importando os módulos

// No AES utiliza-se 9 rodadas mais 2.
// Sendo a primeira apenas um xor com a chave
// e a última não tem a etapa `mixColumns`.
import { firstRound, middleRound, lastRound,
         firstRoundInv, middleRoundInv, lastRoundInv } from './steps'

import { compose } from './utils'

// Algoritmo de expansão de chave.
// Nessa implementação suportamos apenas uma chave de 128 bits.
// É nesse algoritmo que pegamos a chave inicial devolvemos 10 novas chaves.
// A chave inicial mais as novas 10 chaves formam
// as 11 chaves necessárias para as 11 rodadas da encriptação.
import expandKey from './expandKey'

// ### Encriptando

// Esta função recebe uma chave e devolve 3 funções para serem utilizadas na encriptação.
// O segundo argumento é definido automaticamente com base no primeiro.
const encryptRounds = (key, keys = expandKey(key)) =>
  [
    // O último round é servido primeiro, ele recebe a última chave.
    state => lastRound(state, keys[keys.length-1]),
    // Os rounds do meio passam por um reduce, assim eles rodarão n-2 vezes.
    // Sendo n a quantidade total de rounds.
    state => keys.slice(1, -1).reduce(middleRound, state),
    // O primeiro round recebe a primeira chave e é servido por último.
    state => firstRound(state, keys[0])
  ]

// A encriptação é uma composição com a saída de `encryptRounds`.
// Essa composição recebe o texto plano e serve como `Uint8Array`
export const encrypt = (plain, key) =>
  new Uint8Array(
    compose(...encryptRounds(key))(plain)
  )

// ### Decriptando

// Essa função é bem parecida com a `encrypRounds` em sua estrutura.
// Ela usa as versões inversas dos rounds e as chaves espandidas são servidas de forma reversa.
const decryptRounds = (key, keys = expandKey(key).reverse()) =>
  [
    state => lastRoundInv(state, keys[keys.length-1]),
    state => keys.slice(1, -1).reduce(middleRoundInv, state),
    state => firstRoundInv(state, keys[0])
  ]

// O processo de decriptação é idêntico ao de encriptação, porém utilizando o `decryptRounds`
// para a composição.
export const decrypt = (cipher, key) =>
  new Uint8Array(
    compose(...decryptRounds(key))(cipher)
  )

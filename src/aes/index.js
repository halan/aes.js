// ## Aviso
//
// Este código não tem pretensão de ser utilizado em produção. Foco didático:
// mostrar o algoritmo criptográfico e exemplificar programação funcional em
// ES6+. Para encriptação real, prefira a
// [Web Crypto API](https://developer.mozilla.org/pt-BR/docs/Web/API/Web_Crypto_API)
// ou bibliotecas como [crypto-js](https://github.com/brix/crypto-js).

// ## Resumo
//
// Lógica de alto nível do AES-128:
//   - Expandir a chave de 128 bits em 11 chaves do mesmo tamanho
//   - Aplicar a primeira rodada (apenas XOR com a chave original)
//   - Aplicar 9 rodadas intermediárias com as 9 chaves do meio
//   - Aplicar a rodada final (sem `mixColumns`) com a última chave
//
// [Descrição na Wikipedia](https://pt.wikipedia.org/wiki/Advanced_Encryption_Standard#Descri.C3.A7.C3.A3o_de_Cifra) ·
// [Detalhes dos cálculos](http://pt.stackoverflow.com/a/43665)

import {
  firstRound, middleRound, lastRound,
  firstRoundInv, middleRoundInv, lastRoundInv
} from './rounds/index.js'

import {
  pipe, compose, map, head, last, middle, reverse
} from '../utils.js'

import expandKey from './expandKey.js'

// Compõe uma sequência de rounds — um por chave — num único pipe.
const applyRounds = fn => keys => pipe(...map(fn)(keys))

// A estrutura de cifrar e decifrar é a mesma: primeiro round com a primeira
// chave, miolo com as do meio, último round com a última. A diferença é o
// conjunto de transformações usadas. Construímos `cipher` como um *higher-order*
// que monta o pipe a partir das três variantes de round.
const cipher = (first, middleRnd, lastRnd) => keys =>
  pipe(
    first(head(keys)),
    applyRounds(middleRnd)(middle(keys)),
    lastRnd(last(keys)),
    Buffer.from
  )

const encryptRounds = cipher(firstRound, middleRound, lastRound)
const decryptRounds = cipher(firstRoundInv, middleRoundInv, lastRoundInv)

// `encrypt` é a composição direta: expandir a chave, aplicar os rounds.
// `decrypt` é igual, mas com a lista de chaves expandidas invertida.
const encrypt = compose(encryptRounds, expandKey)
const decrypt = compose(decryptRounds, reverse, expandKey)

export { decrypt, encrypt }

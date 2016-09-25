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

// `isFirst` e `isLast` recebem um array e um item
// e respondem a relação desse item com o array.
import { isFirst, isLast } from './utils'

// Algoritmo de expansão de chave.
// Nessa implementação suportamos apenas uma chave de 128 bits.
// É nesse algoritmo que pegamos a chave inicial devolvemos 10 novas chaves.
// A chave inicial mais as novas 10 chaves formam
// as 11 chaves necessárias para as 11 rodadas da encriptação.
import expandKey from './expandKey'

// ### Definindo o loop principal (`reducer`)

// Este reducer aplica as etapas corretas, a primeira, as normais e a última.
const reducer = ({ keys, buffer }, key) => {
  if( isFirst(keys, key) )
    return { keys, buffer: firstRound(buffer, key) }

  else if( isLast(keys, key) )
    return { keys, buffer: lastRound(buffer, key) }

  return { keys, buffer: middleRound(buffer, key) }
}

const reducerInv = ({ keys, buffer }, key) => {
  if( isFirst(keys, key) )
    return { keys, buffer: firstRoundInv(buffer, key) }

  else if( isLast(keys, key) )
    return { keys, buffer: lastRoundInv(buffer, key) }

  return { keys, buffer: middleRoundInv(buffer, key) }
}

// ### Encriptando
export const encrypt = (buffer, key) => {
  // Pego a chave original e expando para 11 chaves.
  const keys = expandKey(key)

  // A partir das 11 chaves, aplico o reducer para encriptar.
  // Feito a encriptação, jogo o resultado em um `Uint8Array`.
  // Estruturas `Uint8Array` são arrays de números de 0 a 255, ou seja, 1 byte, ou seja 1 caractere.
  // Em um `Uint8Array` se eu pego um valor de 250 e somo 10 o resultado *armazenado* será 4!
  return new Uint8Array(
    keys.reduce(reducer, { keys, buffer }).buffer
  )
}

export const decrypt = (buffer, key) => {
  const keys = expandKey(key).reverse()

  return new Uint8Array(
    keys.reduce(reducerInv, { keys, buffer }).buffer
  )
}

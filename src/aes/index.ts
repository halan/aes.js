// ## Núcleo AES-128 — encriptação e decriptação
//
// Lógica de alto nível do AES-128:
//   - Expandir a chave de 128 bits em 11 round keys
//   - Aplicar a primeira rodada (apenas XOR com a chave original)
//   - Aplicar 9 rodadas intermediárias com as chaves do meio
//   - Aplicar a rodada final (sem `mixColumns`) com a última chave

import {
  firstRound, middleRound, lastRound,
  firstRoundInv, middleRoundInv, lastRoundInv,
} from './rounds/index.ts'
import { pipe, head, last, middle } from '../utils.ts'
import expandKey from './expandKey.ts'
import type { Block, BlockLike, Key, RoundKeys } from '../types.ts'

type Round = (key: Block) => (state: Block) => Block

// Compõe uma sequência de rounds — um por chave — via `reduce` direto. Não
// usamos `pipe(...keys.map(fn))` aqui porque o spread variádico apaga a
// aridade do array no nível de tipo, e as overloads de `pipe` (fixas em até
// 6 funções) deixam de bater: o TS cai na assinatura `Fn<unknown, unknown>[]`
// e perdemos a propagação do tipo `Block` ao longo da cadeia. O `reduce`
// preserva `Block → Block` em cada passo.
const applyRounds = (fn: Round) => (keys: readonly Block[]) =>
  (input: Block): Block =>
    keys.reduce<Block>((acc, key) => fn(key)(acc), input)

// A estrutura de cifrar e decifrar é a mesma: primeiro round com a primeira
// chave, miolo com as do meio, último round com a última. Construímos `cipher`
// como um *higher-order* que monta o pipe a partir das três variantes de round.
const cipher = (first: Round, middleRnd: Round, lastRnd: Round) =>
  (keys: RoundKeys) =>
    pipe(
      first(head(keys)),
      applyRounds(middleRnd)(middle(keys)),
      lastRnd(last(keys)),
      (state: Block) => Buffer.from(state),
    )

const encryptRounds = cipher(firstRound, middleRound, lastRound)
const decryptRounds = cipher(firstRoundInv, middleRoundInv, lastRoundInv)

// Converte qualquer `BlockLike` (Buffer, Uint8Array, array) num `Block`
// regular. Coercão única no boundary do AES.
const toBlock = (b: BlockLike): Block => Array.from(b)

// `reverseKeys` é o `reverse` específico de `RoundKeys` — preserva a
// cardinalidade-11 que se perde com `[...rks].reverse()` (`Block[]`).
const reverseKeys = (rks: RoundKeys): RoundKeys =>
  [...rks].reverse() as unknown as RoundKeys

// `encrypt` e `decrypt`: aceita qualquer `BlockLike`, devolve `Buffer`.
const encrypt = (key: Key) =>
  (state: BlockLike): Buffer =>
    encryptRounds(expandKey(key))(toBlock(state))

const decrypt = (key: Key) =>
  (state: BlockLike): Buffer =>
    decryptRounds(reverseKeys(expandKey(key)))(toBlock(state))

export { decrypt, encrypt }

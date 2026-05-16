// ## Combinadores e helpers funcionais

import type { Byte, Bytes } from './types.ts'

type Fn<A, B> = (a: A) => B


// ### Combinadores básicos

export const id = <A>(x: A): A => x

export const constant = <A>(x: A) => (): A => x

// Duplica um valor numa tupla `[x, x]` (combinador `W`). Em JS puro permite
// expressar `scanl` como caso particular de `mapAccumL`; em TS preferimos
// definir `scanl` separadamente para evitar perda de precisão de tipos.
//
// Atenção: as duas posições compartilham a *mesma* referência. O pipeline
// é puro, mas consumidores devem tratar as saídas como imutáveis.
export const dup = <A>(x: A): readonly [A, A] => [x, x]

export const flip = <A, B, C>(fn: (a: A) => (b: B) => C) =>
  (b: B) => (a: A): C => fn(a)(b)


// ### Composição

// `pipe` e `compose` são tipados com overloads até 6 funções. Acima disso, a
// resolução cai no assinatura de implementação (`Fn<unknown, unknown>[]`) e
// o pipeline perde precisão — por isso usamos `reduce` direto em `applyRounds`.

export function compose<A>(): Fn<A, A>
export function compose<A, B>(f: Fn<A, B>): Fn<A, B>
export function compose<A, B, C>(f: Fn<B, C>, g: Fn<A, B>): Fn<A, C>
export function compose<A, B, C, D>(f: Fn<C, D>, g: Fn<B, C>, h: Fn<A, B>): Fn<A, D>
export function compose<A, B, C, D, E>(f: Fn<D, E>, g: Fn<C, D>, h: Fn<B, C>, i: Fn<A, B>): Fn<A, E>
export function compose<A, B, C, D, E, F>(f: Fn<E, F>, g: Fn<D, E>, h: Fn<C, D>, i: Fn<B, C>, j: Fn<A, B>): Fn<A, F>
export function compose(...fns: Fn<unknown, unknown>[]): Fn<unknown, unknown> {
  return (x) => fns.reduceRight<unknown>((v, f) => f(v), x)
}

export function pipe<A>(): Fn<A, A>
export function pipe<A, B>(f1: Fn<A, B>): Fn<A, B>
export function pipe<A, B, C>(f1: Fn<A, B>, f2: Fn<B, C>): Fn<A, C>
export function pipe<A, B, C, D>(f1: Fn<A, B>, f2: Fn<B, C>, f3: Fn<C, D>): Fn<A, D>
export function pipe<A, B, C, D, E>(f1: Fn<A, B>, f2: Fn<B, C>, f3: Fn<C, D>, f4: Fn<D, E>): Fn<A, E>
export function pipe<A, B, C, D, E, F>(f1: Fn<A, B>, f2: Fn<B, C>, f3: Fn<C, D>, f4: Fn<D, E>, f5: Fn<E, F>): Fn<A, F>
export function pipe<A, B, C, D, E, F, G>(f1: Fn<A, B>, f2: Fn<B, C>, f3: Fn<C, D>, f4: Fn<D, E>, f5: Fn<E, F>, f6: Fn<F, G>): Fn<A, G>
export function pipe(...fns: Fn<unknown, unknown>[]): Fn<unknown, unknown> {
  return (x) => fns.reduce<unknown>((v, f) => f(v), x)
}


// ### Listas — decomposição clássica

// `NonEmpty<A>` é o tipo de listas garantidamente não-vazias. Necessário para
// que `head`/`last` retornem `A` em vez de `A | undefined`.
type NonEmpty<A> = readonly [A, ...A[]]

export const head = <A>([x]: NonEmpty<A>): A => x

export const tail = <A>([, ...rest]: NonEmpty<A>): A[] => rest

export const init = <A>(arr: readonly A[]): A[] => arr.slice(0, -1)

export const last = <A>(arr: NonEmpty<A>): A => arr[arr.length - 1] as A

// `middle = init ∘ tail` — o miolo de uma lista (tudo menos primeiro e último).
// Não exigimos não-vacuidade do resultado: passar uma lista de 2 elementos
// produz `[]` legitimamente.
export const middle = <A>(arr: NonEmpty<A>): A[] => arr.slice(1, -1)

export const reverse = <A>(arr: readonly A[]): A[] => [...arr].reverse()

export const map = <A, B>(fn: (a: A) => B) =>
  (arr: readonly A[]): B[] => arr.map(fn)

export const reduce = <A, B>(fn: (acc: B, x: A) => B, ini: B) =>
  (arr: readonly A[]): B => arr.reduce(fn, ini)

export const flat = <A>(arr: readonly (readonly A[])[]): A[] =>
  arr.reduce<A[]>((acc, xs) => [...acc, ...xs], [])

// `permute(indices)(arr)` produz um novo array onde a posição `j` recebe
// `arr[indices[j]]`. Útil para reordenações fixas como `shiftRows`.
export const permute = <A>(indices: readonly number[]) =>
  (arr: readonly A[]): A[] =>
    indices.map((i) => {
      const v = arr[i]
      if (v === undefined) {
        throw new Error(`permute: index ${i} out of bounds (length ${arr.length})`)
      }
      return v
    })

// `partition(n)(arr)` divide um array em pedaços de tamanho `n`. Definição
// recursiva sobre cabeça/cauda no estilo clássico. JS não tem TCO, portanto
// entradas muito grandes pagam o preço de um stack frame por chunk.
export const partition = (size: number) =>
  <A>(arr: readonly A[]): A[][] =>
    arr.length === 0
      ? []
      : [arr.slice(0, size), ...partition(size)<A>(arr.slice(size))]

const WORD_SIZE = 4

export const splitInWords: <A>(arr: readonly A[]) => A[][] = partition(WORD_SIZE)

export const lastWord = <A>(arr: readonly A[]): A[] => arr.slice(-WORD_SIZE)


// ### `mapAccumL` e `scanl`

// `mapAccumL(fn)(estadoInicial)(arr)` percorre `arr` carregando um estado
// arbitrário; cada passo devolve `[novoEstado, saída]`. Devolve a lista de
// saídas (o estado final é descartado).
//
// Usado em CBC decrypt: o estado é o bloco *cifrado* anterior; a saída é o
// bloco *plaintext* recuperado.
export const mapAccumL = <S, A, B>(fn: (state: S) => (x: A) => readonly [S, B]) =>
  (ini: S) =>
  (arr: readonly A[]): B[] =>
    arr.reduce<readonly [S, B[]]>(
      ([state, out], x) => {
        const [next, value] = fn(state)(x)
        return [next, [...out, value]]
      },
      [ini, []]
    )[1]

// `scanl(fn)(ini)(arr)` é um `reduce` que devolve todos os passos intermediários.
// Equivalente a `mapAccumL` onde o estado e a saída coincidem — em JS puro
// expressamos como `mapAccumL(s => x => dup(fn(s)(x)))`. Em TS, tipar essa
// equivalência exigiria convencer o compilador de que o estado e a saída
// coincidem, e por isso preferimos uma implementação independente. A
// equivalência permanece como insight pedagógico no `dup`.
//
// Exemplo: `scanl(a => b => a + b)(0)([1, 2, 3]) === [1, 3, 6]`.
export const scanl = <S, A>(fn: (state: S) => (x: A) => S) =>
  (ini: S) =>
  (arr: readonly A[]): S[] => {
    const result: S[] = []
    arr.reduce<S>((state, x) => {
      const next = fn(state)(x)
      result.push(next)
      return next
    }, ini)
    return result
  }


// ### AES-específico

// xor byte a byte. Exige tamanhos iguais — tamanhos divergentes seriam
// silenciosamente toleráveis (bytes em excesso passariam intactos), o que
// mascararia IV/chave de tamanho errado em vez de falhar explicitamente.
export const xor = (left: Bytes) => (right: Bytes): Byte[] => {
  if (left.length !== right.length) {
    throw new Error(`xor: mismatched lengths (${left.length} vs ${right.length})`)
  }
  return right.map((b, i) => (left[i] as Byte) ^ b)
}

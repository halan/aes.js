// ## Combinadores básicos

// Identidade: devolve o que recebe. Em composições serve como elemento neutro.
const id = x => x

// Constante (combinador `K`): ignora a entrada e devolve sempre `x`.
const constant = x => () => x

// Duplica um valor numa tupla `[x, x]` (combinador `W`). Permite expressar
// `scanl` como um caso particular de `mapAccumL` — onde o estado a propagar
// coincide com a saída a registrar.
//
// Atenção: as duas posições são a *mesma* referência. O pipeline atual é puro,
// mas se algum passo futuro mutar um bloco no lugar, a história do `scanl`
// será reescrita retroativamente. Consumidores devem tratar as saídas como
// imutáveis.
const dup = x => [x, x]

// Inverte a ordem dos dois primeiros argumentos de uma função curried.
const flip = fn => a => b => fn(b)(a)

// Composição da direita para a esquerda: `compose(f, g)(x) === f(g(x))`.
const compose = (...fns) => x => fns.reduceRight((v, f) => f(v), x)

// Composição da esquerda para a direita: `pipe(f, g)(x) === g(f(x))`.
const pipe = (...fns) => x => fns.reduce((v, f) => f(v), x)


// ## Listas — decomposição clássica

const head = ([x]) => x
const tail = ([, ...rest]) => rest
const init = arr => arr.slice(0, -1)
const last = arr => arr[arr.length - 1]

// Atalho usado pelos rounds: o "miolo" de uma lista (tudo menos primeiro e último).
const middle = compose(init, tail)

const reverse = arr => [...arr].reverse()
const map = fn => arr => arr.map(fn)
const reduce = (fn, ini) => arr => arr.reduce(fn, ini)
const flat = reduce((acc, x) => [...acc, ...x], [])

// `permute(indices)(arr)` produz um novo array onde a posição `j` recebe
// `arr[indices[j]]`. Útil para reordenações fixas como o `shiftRows`.
const permute = indices => arr => indices.map(i => arr[i])

// `partition(n)(arr)` divide um array em pedaços de tamanho `n`. Definido
// recursivamente sobre cabeça/cauda no estilo clássico. JS não tem TCO,
// portanto entradas muito grandes pagam o preço de um stack frame por chunk.
const partition = size => arr =>
  arr.length === 0
    ? []
    : [arr.slice(0, size), ...partition(size)(arr.slice(size))]

const WORD_SIZE = 4
const splitInWords = partition(WORD_SIZE)
const lastWord = arr => arr.slice(-WORD_SIZE)


// ## Recursão estruturada — `scanl` e `mapAccumL`

// `mapAccumL(fn)(estadoInicial)(arr)` percorre `arr` carregando um estado.
// A cada passo `fn(estado)(x)` devolve `[novoEstado, saída]`. O resultado é
// a lista de saídas (o estado final é descartado).
//
// Usado em CBC decrypt: o estado é o bloco *cifrado* anterior, a saída é o
// bloco *plaintext* recém-recuperado.
const mapAccumL = fn => ini => arr =>
  arr.reduce(
    ([state, out], x) => {
      const [next, value] = fn(state)(x)
      return [next, [...out, value]]
    },
    [ini, []]
  )[1]

// `scanl(fn)(ini)(arr)` é um `reduce` que devolve todos os passos intermediários.
// Definido como `mapAccumL` onde o estado e a saída coincidem — daí o uso de `dup`.
// Exemplo: `scanl(a => b => a + b)(0)([1, 2, 3]) === [1, 3, 6]`.
//
// CBC encrypt é um `scanl` puro: cada bloco cifrado depende do anterior.
// A expansão de chave do AES também: cada nova chave deriva da anterior.
const scanl = fn => mapAccumL(state => x => dup(fn(state)(x)))


// ## AES-específico

// xor byte a byte. Exige tamanhos iguais — tamanhos divergentes seriam
// silenciosamente toleráveis (bytes em excesso passariam intactos), o que
// mascararia IV/chave de tamanho errado em vez de falhar explicitamente.
const xor = left => right => {
  if (left.length !== right.length) {
    throw new Error(`xor: mismatched lengths (${left.length} vs ${right.length})`)
  }
  return right.map((b, i) => left[i] ^ b)
}


export {
  id, constant, dup, flip, compose, pipe,
  head, tail, init, last, middle,
  reverse, map, reduce, flat,
  permute, partition, splitInWords, lastWord,
  mapAccumL, scanl,
  xor,
}

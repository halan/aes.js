const partition = size => arr =>
  arr.reduce(([head = [], ...rest], x) =>
    head.length >= size
      ? [[x], head, ...rest]
      : [[...head, x], ...rest]
  , []).reverse()

// Constante pra definir o tamanho em bytes de um word: `4`.
// Esta é utilizada tanto para `lastWord` quanto para `splitInWords`.
const WORD_SIZE = 4

// Função auxiliar que devolve a última words.
// Na prática: retorna um array com os 4 últimos elementos.
const lastWord = arr => arr.length && arr.slice(-WORD_SIZE)

// Função auxiliar que divide um array em words, ou seja, divide em grupos de 4 elementos.
const splitInWords = partition(WORD_SIZE)

// map, reduce, reverse e flat escritos de forma a facilitar construções utilizando pipe
const map = fn => arr =>
  arr.map(fn)

const reduce = (fn, ini) => arr =>
  arr.reduce(fn, ini)

const reverse = arr =>
  arr.reverse()

const flat =
  reduce((arr, x) => [...arr, ...x], [])

// pipe(fn1, fn2)(dado) equivale a fn2(fn1(dado))
const pipe = (...fns) => x =>
  fns.reduce((v, f) => f(v), x);

// xor byte a byte
const xor = left => map((b, i) => left[i] ^ b)

// Essa função aplica uma função sobre cada valor e seu valor anterior num array
// O valor de ini é aplicado sobre o primeiro valor da array
// chainBlocks(x => y => x + y)(10)([1, 2, 3, 4]) -> [11, 13, 16, 20]
const chainBlocks = fn => ini =>
  pipe(
    map(fn),
    reduce(([last, ...rest], partialFn) => [
      partialFn(last || ini),
      ...(last ? [last] : []),
      ...rest
    ], []),
    reverse
  )

const chainBlocksInv = fn => ini =>
  pipe(
    reduce(([arr, last], curr) => [
      [ ...arr, fn(last)(curr)],
      curr
    ], [[], ini]),
    ([arr, last]) => arr
  )



module.exports = {
  lastWord,
  partition,
  splitInWords,
  pipe,
  xor,
  map,
  reduce,
  flat,
  chainBlocks,
  chainBlocksInv,
  reverse
}

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

// map, reduce, reverse e toUint8 escritos de forma a facilitar construções utilizando pipe
const map = fn => arr =>
  arr.map(fn)

const reduce = (fn, ini) => arr =>
  arr.reduce(fn, ini)

const reverse = arr =>
  arr.reverse()

const toUint8 = arr =>
  new Uint8Array(arr)

// pipe(fn1, fn2)(dado) equivale a fn2(fn1(dado))
const pipe = (...fn) => x =>
  fn.reduce((v, f) => f(v), x);

// xor byte a byte
const xor = left => map((b, i) => left[i] ^ b)

module.exports = { lastWord, splitInWords, pipe, xor, map, reduce, toUint8, reverse }

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

const compose = (...fn) => x =>
  fn.reduceRight((v, f) => f(v), x);

const map = fn => arr =>
  arr.map(fn)

const reduce = (fn, ini) => arr =>
  arr.reduce(fn, ini)

const reverse = arr =>
  arr.reverse()

const toUint8 = arr =>
  new Uint8Array(arr)

// xor byte a byte
const xor = left => map((b, i) => left[i] ^ b)

module.exports = { lastWord, splitInWords, compose, xor, map, reduce, toUint8, reverse }

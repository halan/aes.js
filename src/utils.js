// https://medium.com/@dtipson/creating-an-es6ish-compose-in-javascript-ac580b95104a
export const compose = (fn, ...rest) => 
  rest.length === 0 ? fn : (...args) => fn(compose(...rest)(...args))

// https://gist.github.com/webinista/11240585#gistcomment-1781756
export const group = (arr, size) =>
  arr.reduce((a,b,i,g) =>
    !(i % size) ? (a.push(g.slice(i, i + size)), a) : a, [])

export const isFirst = (arr, item) => arr.indexOf(item) === 0
export const isLast = (arr, item) => arr.indexOf(item) === arr.length-1

export const xor = (left, right) => right.map( (b, i) => left[i] ^ b)

// Constante pra definir o tamanho em bytes de um word: `4`
const WORD_SIZE = 4

// Função auxiliar que devolve as últimas words. A ideia aqui é pegar a primeira word da última chave.
export const lastWord = arr => arr.slice(-WORD_SIZE)

// Função auxiliar que divide um array em words, ou seja, divide em grupos de 4 elementos.
export const splitInWords = arr => group(arr, WORD_SIZE)

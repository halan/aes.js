// Pesquisando por uma função que quebre um array em pedaços iguais
// esbarrei nesse [gist](https://gist.github.com/webinista/11240585#gistcomment-1781756).
const group = (arr, size) =>
  arr.reduce((a,b,i,g) =>
    !(i % size) ? (a.push(g.slice(i, i + size)), a) : a, [])

// Constante pra definir o tamanho em bytes de um word: `4`.
// Esta é utilizada tanto para `lastWord` quanto para `splitInWords`.
const WORD_SIZE = 4

// Função auxiliar que devolve a última words.
// Na prática: retorna um array com os 4 últimos elementos.
const lastWord = arr => arr.slice(-WORD_SIZE)

// Função auxiliar que divide um array em words, ou seja, divide em grupos de 4 elementos.
const splitInWords = arr => group(arr, WORD_SIZE)

// Pesquisando sobre uma função pequena escrita com es6 que faça um compose
// achei esse materiao [aqui](https://medium.com/@dtipson/creating-an-es6ish-compose-in-javascript-ac580b95104a).
const compose = (fn, ...rest) => 
  rest.length === 0 ? fn : (...args) => fn(compose(...rest)(...args))

// xor byte a byte
const xor = (left, right) => right.map( (b, i) => left[i] ^ b)

module.exports = { lastWord, splitInWords, compose, xor }

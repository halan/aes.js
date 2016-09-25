// Pesquisando sobre uma função pequena escrita com es6 que faça um compose
// achei esse materiao [aqui](https://medium.com/@dtipson/creating-an-es6ish-compose-in-javascript-ac580b95104a).
export const compose = (fn, ...rest) => 
  rest.length === 0 ? fn : (...args) => fn(compose(...rest)(...args))

// Pesquisando por uma função que quebre um array em pedaços iguais
// esbarrei nesse [gist](https://gist.github.com/webinista/11240585#gistcomment-1781756).
export const group = (arr, size) =>
  arr.reduce((a,b,i,g) =>
    !(i % size) ? (a.push(g.slice(i, i + size)), a) : a, [])

// Funções simples de pergunta sobre a posição de um ítem, se é o primeiro ou se é o último.
export const isFirst = (arr, item) => arr.indexOf(item) === 0
export const isLast = (arr, item) => arr.indexOf(item) === arr.length-1

// xor byte a byte
export const xor = (left, right) => right.map( (b, i) => left[i] ^ b)

// Constante pra definir o tamanho em bytes de um word: `4`.
// Esta é utilizada tanto para `lastWord` quanto para `splitInWords`.
const WORD_SIZE = 4

// Função auxiliar que devolve a última words.
// Na prática: retorna um array com os 4 últimos elementos.
export const lastWord = arr => arr.slice(-WORD_SIZE)

// Função auxiliar que divide um array em words, ou seja, divide em grupos de 4 elementos.
export const splitInWords = arr => group(arr, WORD_SIZE)

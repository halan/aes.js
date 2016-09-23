export default (left, right) => right.map( (b, i) => left[i] ^ b)

// ![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/320px-AES-ShiftRows.svg.png)
//
// O shiftRows apenas embaralha as posições.
export default b =>
  [ 0,  5, 10, 15,
    4,  9, 14,  3,
    8, 13,  2,  7,
   12,  1,  6,  11].map( i => b[i] )

// A sua versão invertida apenas desembaralha
export const shiftRowsInv = b =>
  [ 0, 13, 10,  7,
    4,  1, 14, 11,
    8,  5,  2, 15,
   12,  9,  6,  3].map( i => b[i] )

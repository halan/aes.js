// ![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/AES-ShiftRows.svg/320px-AES-ShiftRows.svg.png)
//
// `shiftRows` é uma permutação fixa das 16 posições do estado. A versão inversa
// é a permutação que desfaz a primeira. Expressamos ambas como `permute` sobre
// arrays de índices — a operação fica explícita no dado.

import { permute } from '../../utils.ts'
import type { Block, Permutation16 } from '../../types.ts'

const SHIFT_ROWS: Permutation16 = [
   0,  5, 10, 15,
   4,  9, 14,  3,
   8, 13,  2,  7,
  12,  1,  6, 11,
]

const SHIFT_ROWS_INV: Permutation16 = [
   0, 13, 10,  7,
   4,  1, 14, 11,
   8,  5,  2, 15,
  12,  9,  6,  3,
]

export const shiftRows: (b: Block) => Block = permute(SHIFT_ROWS)
export const shiftRowsInv: (b: Block) => Block = permute(SHIFT_ROWS_INV)

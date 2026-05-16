// ![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ad/AES-AddRoundKey.svg/320px-AES-AddRoundKey.svg.png)
//
// `addRoundKey` é apenas um xor byte a byte. Como o XOR é involutivo,
// `addRoundKey` é seu próprio inverso — daí a ausência de `addRoundKeyInv`.

import { xor } from '../../utils.ts'
import type { Block } from '../../types.ts'

export const addRoundKey: (key: Block) => (state: Block) => Block = xor

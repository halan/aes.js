// ![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ad/AES-AddRoundKey.svg/320px-AES-AddRoundKey.svg.png)
//
// `addRoundKey` é apenas um xor byte a byte

import { xor } from '../../utils.js'

export const addRoundKey = xor

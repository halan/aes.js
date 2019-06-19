// ![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ad/AES-AddRoundKey.svg/320px-AES-AddRoundKey.svg.png)
//
// `addRoundKey` é apenas um xor byte a byte

const { xor } = require('../utils')

module.exports = {
  addRoundKey: (left, right) => xor(left)(right)
}

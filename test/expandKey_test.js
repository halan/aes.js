const { expect } = require('chai')
const expandKey = require('expandKey')

describe('expandKey', () => {
  it('expand key', () => {
    expect(expandKey(
       [ 15,  21, 113, 201,  71, 217, 232,  89,  12, 183, 173, 214, 175, 127, 103, 152]
    )).to.be.deep.equal(
      [new Uint8Array([ 15,  21, 113, 201,  71, 217, 232,  89,  12, 183, 173, 214, 175, 127, 103, 152]),
       new Uint8Array([220, 144,  55, 176, 155,  73, 223, 233, 151, 254, 114,  63,  56, 129,  21, 167]),
       new Uint8Array([210, 201, 107, 183,  73, 128, 180,  94, 222, 126, 198,  97, 230, 255, 211, 198]),
       new Uint8Array([192, 175, 223,  57, 137,  47, 107, 103,  87,  81, 173,   6, 177, 174, 126, 192]),
       new Uint8Array([ 44,  92, 101, 241, 165, 115,  14, 150, 242,  34, 163, 144,  67, 140, 221,  80]), 
       new Uint8Array([ 88, 157,  54, 235, 253, 238,  56, 125,  15, 204, 155, 237,  76,  64,  70, 189]),
       new Uint8Array([113, 199,  76, 194, 140,  41, 116, 191, 131, 229, 239,  82, 207, 165, 169, 239]),
       new Uint8Array([ 55,  20, 147,  72, 187,  61, 231, 247,  56, 216,   8, 165, 247, 125, 161,  74]), 
       new Uint8Array([ 72,  38,  69,  32, 243,  27, 162, 215, 203, 195, 170, 114,  60, 190,  11,  56]),
       new Uint8Array([253,  13,  66, 203,  14,  22, 224,  28, 197, 213,  74, 110, 249, 107,  65,  86]), 
       new Uint8Array([180, 142, 243,  82, 186, 152,  19,  78, 127,  77,  89,  32, 134,  38,  24, 118])]
    )
  })
})

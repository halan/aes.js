const { expect } = require('chai')
const { shiftRows, shiftRowsInv } = require('aes/rounds')

describe('shiftRows', () => {
  it('shift rows', () => {
    expect(shiftRows(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )).to.be.deep.equal(
      [164, 64,  15,  245,
        14, 236, 172, 200,
       114,  72, 204,  78,
       117, 253,  63, 228]
    )
  })

  it('shift rows inverse', () => {
    expect(shiftRowsInv(
      [164, 64,  15,  245,
        14, 236, 172, 200,
       114,  72, 204,  78,
       117, 253,  63, 228]
    )).to.be.deep.equal(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )
  })

  it('shift rows could be reverted by shift rows inverse', () => {
    expect(shiftRowsInv(shiftRows(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    ))).to.be.deep.equal(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )

    expect(shiftRows(shiftRowsInv(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    ))).to.be.deep.equal(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )
  })
})


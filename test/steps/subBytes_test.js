const { expect } = require('chai')
const { subBytes, subBytesInv } = require('steps')

describe('subBytes', () => {
  it('sub bytes', () => {
    expect(subBytes(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    )).to.be.deep.equal(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )
  })

  it('sub bytes inverse', () => {
    expect(subBytesInv(
      [164, 253, 204, 200,
        14,  64,  63,  78,
       114, 236,  15, 228,
       117,  72, 172, 245]
    )).to.be.deep.equal(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    )
  })

  it('sub bytes could be reverted by sub bytes inverse', () => {
    expect(subBytes(subBytesInv(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    ))).to.be.deep.equal(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    )
    
    expect(subBytesInv(subBytes(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    ))).to.be.deep.equal(
      [29,  33, 39,  177,
      215, 114, 37,  182,
       30, 131, 251, 174,
       63, 212, 170, 119]
    )
  })
})

import { expect } from 'chai'
import { subBytes } from 'steps'

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
})

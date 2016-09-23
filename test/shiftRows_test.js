import { expect } from 'chai'
import { shiftRows } from '../src/steps'

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
})


import { expect } from 'chai'
import AES from 'index'

describe('AES', () => {
  it('basic encrypt', () => {
    const plain =     new Uint8Array([ 18,  52,  86, 120, 144, 171, 205, 239,  18,  52,  86, 120, 144, 171, 205, 239])
    const key =       new Uint8Array([ 15,  21, 113, 201,  71, 217, 232,  89,  12, 183, 173, 214, 175, 127, 103, 152])
    const encrypted = new Uint8Array([218,  36, 238, 175, 161, 189, 151, 108,  68,  36, 159, 192, 152,  50, 155, 147])

    expect(AES(plain, key)).to.be.deep.equal(encrypted)
  }) 
})

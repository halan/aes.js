import { expect } from 'chai'
import { pksc7, pksc7Inv } from '#padding'

describe('PKCS#7 padding', () => {
  it('pads a partial block up to the target size', () => {
    const padded = pksc7(16)('hello')
    expect(padded.length).to.be.equal(16)
    expect(padded.slice(-11).every(b => b === 11)).to.be.true
  })

  it('appends a full block when input is already aligned', () => {
    const padded = pksc7(16)('sixteen bytes!!!')
    expect(padded.length).to.be.equal(32)
    expect(padded.slice(-16).every(b => b === 16)).to.be.true
  })

  it('round-trips with pksc7Inv', () => {
    const original = Buffer.from('arbitrary message')
    expect(pksc7Inv(pksc7(16)(original))).to.be.deep.equal(original)
  })
})

describe('PKCS#7 unpad validation', () => {
  it('rejects a zero last byte', () => {
    expect(() => pksc7Inv(Buffer.alloc(16, 0))).to.throw(/PKCS#7/)
  })

  it('rejects a last byte larger than the block size', () => {
    const bad = Buffer.alloc(16, 0x11)
    bad[15] = 17
    expect(() => pksc7Inv(bad)).to.throw(/PKCS#7/)
  })

  it('rejects inconsistent padding bytes', () => {
    const bad = Buffer.alloc(16, 0xAA)
    bad[15] = 4
    bad[14] = 4
    bad[13] = 4
    bad[12] = 0xCC // should also be 4
    expect(() => pksc7Inv(bad)).to.throw(/PKCS#7/)
  })

  it('rejects empty input', () => {
    expect(() => pksc7Inv(Buffer.alloc(0))).to.throw(/PKCS#7/)
  })
})

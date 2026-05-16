import { expect } from 'chai'
import { encrypt, decrypt } from '#aes'

describe('AES', () => {
  const plain =     Buffer.from("Hola mundo!!!!!!")
  const key =       Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const encrypted = Buffer.from('Y79fni4sH5FkH1OnZrxV7Q==', 'base64')

  it('basic encrypt', () => {
    expect(encrypt(key)(plain)).to.be.deep.equal(encrypted)
  }) 

  it('basic decrypt', () => {
    expect(decrypt(key)(encrypted)).to.be.deep.equal(plain)
  })

})

describe('AES NIST FIPS-197 vectors', () => {
  it('Appendix B (AES-128)', () => {
    const key      = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex')
    const plain    = Buffer.from('3243f6a8885a308d313198a2e0370734', 'hex')
    const expected = Buffer.from('3925841d02dc09fbdc118597196a0b32', 'hex')

    expect(encrypt(key)(plain)).to.be.deep.equal(expected)
    expect(decrypt(key)(expected)).to.be.deep.equal(plain)
  })

  it('Appendix C.1 (AES-128)', () => {
    const key      = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')
    const plain    = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
    const expected = Buffer.from('69c4e0d86a7b0430d8cdb78070b4c55a', 'hex')

    expect(encrypt(key)(plain)).to.be.deep.equal(expected)
    expect(decrypt(key)(expected)).to.be.deep.equal(plain)
  })
})

describe('AES key validation', () => {
  const plain = Buffer.from("Hola mundo!!!!!!")

  it('rejects keys shorter than 16 bytes', () => {
    expect(() => encrypt(Buffer.from('too short'))(plain)).to.throw(/16-byte key/)
  })

  it('rejects keys longer than 16 bytes (AES-192/256 not supported)', () => {
    const key24 = Buffer.alloc(24, 0xaa)
    expect(() => encrypt(key24)(plain)).to.throw(/16-byte key/)
  })
})

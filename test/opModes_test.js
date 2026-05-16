import { expect } from 'chai'
import { encrypt, decrypt } from '#aes'
import { cbc, cbcInv, ecb, ecbInv } from '#opModes'
import crypto from 'node:crypto'

describe('AES CBC', () => {
  const plain = "Hola mundo!!!!!!"
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv = Buffer.from('U2FsdGVkX182re6Lw5wOZQ==', 'base64')

  it('should get the same result than the canon aes-128-cbc', () => {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv) 
    cipher.write(plain)
    cipher.end()
    const encrypted = cipher.read()

    expect(cbc(encrypt(key))(iv)(plain).toString('base64'))
      .to.be.equal(encrypted.toString('base64')) 
  })

  it('should be able to decrypt from buffer', () => {
    const encrypted = Buffer.from('B5tTp68o8zNBgFDsL0muPKPo+OmcDhyuV6exLQJZFZE=', 'base64')

    expect(cbcInv(decrypt(key))(iv)(encrypted).toString('utf8'))
      .to.be.equal(plain)
  })

  it('encrypt and decrypt will just return plain text again', () => {
    expect(
      cbcInv(decrypt(key))(iv)(
        cbc(encrypt(key))(iv)(plain)
      ).toString('utf8')
    ).to.be.equal(plain)
  })
})

describe('AES ECB', () => {
  const plain = "Hola mundo!!!!!!"
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')

  it('should get the same result than the canon aes-128-ecb', () => {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
    cipher.write(plain)
    cipher.end()
    const encrypted = cipher.read()

    expect(ecb(encrypt(key))(plain).toString('base64'))
      .to.be.equal(encrypted.toString('base64'))
  })

  it('should be able to decrypt from buffer', () => {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
    cipher.write(plain)
    cipher.end()
    const encrypted = cipher.read()

    expect(ecbInv(decrypt(key))(encrypted).toString('utf8'))
      .to.be.equal(plain)
  })

  it('encrypt and decrypt will just return plain text again', () => {
    expect(
      ecbInv(decrypt(key))(
        ecb(encrypt(key))(plain)
      ).toString('utf8')
    ).to.be.equal(plain)
  })
})

describe('round-trip on non-block-aligned plaintexts', () => {
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv  = Buffer.from('U2FsdGVkX182re6Lw5wOZQ==', 'base64')

  const cases = [
    ['empty', ''],
    ['shorter than a block', 'short'],
    ['one byte less than a block', 'fifteen bytes!!'],
    ['exactly two blocks', 'thirty-two bytes for two blocks!'],
    ['larger than a block', 'this plaintext is longer than sixteen bytes'],
  ]

  cases.forEach(([label, plain]) => {
    it(`CBC round-trip: ${label} (${Buffer.byteLength(plain)} bytes)`, () => {
      const ct = cbc(encrypt(key))(iv)(plain)
      expect(cbcInv(decrypt(key))(iv)(ct).toString('utf8')).to.be.equal(plain)
    })

    it(`ECB round-trip: ${label} (${Buffer.byteLength(plain)} bytes)`, () => {
      const ct = ecb(encrypt(key))(plain)
      expect(ecbInv(decrypt(key))(ct).toString('utf8')).to.be.equal(plain)
    })
  })
})

describe('CBC tamper detection (via padding validation)', () => {
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv  = Buffer.from('U2FsdGVkX182re6Lw5wOZQ==', 'base64')
  const plain = "Hola mundo!!!!!!"

  it('rejects ciphertext whose last block was tampered with (bad padding)', () => {
    const ct = Buffer.from(cbc(encrypt(key))(iv)(plain))
    ct[ct.length - 1] ^= 0xff
    expect(() => cbcInv(decrypt(key))(iv)(ct)).to.throw(/PKCS#7/)
  })

  it('rejects empty ciphertext', () => {
    expect(() => cbcInv(decrypt(key))(iv)(Buffer.alloc(0))).to.throw(/PKCS#7/)
  })
})

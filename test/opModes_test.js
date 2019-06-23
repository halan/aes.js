const { expect } = require('chai')
const { encrypt, decrypt } = require('aes')
const { cbc, cbcInv } = require('opModes');
const crypto = require('crypto');

describe('AES CBC', () => {
  const plain = "Hola mundo!!!!!!"
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv = Buffer.from('U2FsdGVkX182re6Lw5wOZQ==', 'base64')

  it('should get the same result than the canon aes-128-cbc', () => {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv) 
    cipher.write(plain)
    cipher.end()
    const encrypted = cipher.read()

    expect(cbc(encrypt(key), iv)(plain).toString('base64'))
      .to.be.equal(encrypted.toString('base64')) 
  })

  it('should be able to decrypt from buffer', () => {
    const encrypted = Buffer.from('B5tTp68o8zNBgFDsL0muPKPo+OmcDhyuV6exLQJZFZE=', 'base64')

    expect(cbcInv(decrypt(key), iv)(encrypted).toString('utf8'))
      .to.be.equal(plain)
  })

  it('encrypt and decrypt will just return plain text again', () => {
    expect(
      cbcInv(decrypt(key), iv)(
        cbc(encrypt(key), iv)(plain)
      ).toString('utf8')
    ).to.be.equal(plain)
  })
})

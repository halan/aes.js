const { expect } = require('chai')
const { encrypt, decrypt } = require('aes')

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

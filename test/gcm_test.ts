import { expect } from 'chai'
import { encrypt } from '#aes'
import { gcmEncrypt, gcmDecrypt, GcmAuthError } from '#gcm'

const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex')

// === NIST SP 800-38D Test Vectors (AES-128) ===

describe('AES-GCM — NIST test vectors', () => {
  it('Test Case 1: empty plaintext, empty AAD, zero key/IV', () => {
    const key  = hex('00000000000000000000000000000000')
    const iv   = hex('000000000000000000000000')
    const plain = Buffer.alloc(0)
    const expectedTag = hex('58e2fccefa7e3061367f1d57a4e7455a')

    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    expect(ciphertext).to.deep.equal(Buffer.alloc(0))
    expect(tag).to.deep.equal(expectedTag)
  })

  it('Test Case 2: single zero block, empty AAD, zero key/IV', () => {
    const key  = hex('00000000000000000000000000000000')
    const iv   = hex('000000000000000000000000')
    const plain = hex('00000000000000000000000000000000')
    const expectedCt  = hex('0388dace60b6a392f328c2b971b2fe78')
    const expectedTag = hex('ab6e47d42cec13bdf53a67b21257bddf')

    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    expect(ciphertext).to.deep.equal(expectedCt)
    expect(tag).to.deep.equal(expectedTag)
  })

  it('Test Case 3: 4 blocks plaintext, empty AAD', () => {
    const key   = hex('feffe9928665731c6d6a8f9467308308')
    const iv    = hex('cafebabefacedbaddecaf888')
    const plain = hex(
      'd9313225f88406e5a55909c5aff5269a' +
      '86a7a9531534f7da2e4c303d8a318a72' +
      '1c3c0c95956809532fcf0e2449a6b525' +
      'b16aedf5aa0de657ba637b391aafd255'
    )
    const expectedCt = hex(
      '42831ec2217774244b7221b784d0d49c' +
      'e3aa212f2c02a4e035c17e2329aca12e' +
      '21d514b25466931c7d8f6a5aac84aa05' +
      '1ba30b396a0aac973d58e091473f5985'
    )
    const expectedTag = hex('4d5c2af327cd64a62cf35abd2ba6fab4')

    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    expect(ciphertext).to.deep.equal(expectedCt)
    expect(tag).to.deep.equal(expectedTag)
  })

  it('Test Case 4: with AAD, partial last block', () => {
    const key   = hex('feffe9928665731c6d6a8f9467308308')
    const iv    = hex('cafebabefacedbaddecaf888')
    const plain = hex(
      'd9313225f88406e5a55909c5aff5269a' +
      '86a7a9531534f7da2e4c303d8a318a72' +
      '1c3c0c95956809532fcf0e2449a6b525' +
      'b16aedf5aa0de657ba637b39'
    )
    const aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    const expectedCt = hex(
      '42831ec2217774244b7221b784d0d49c' +
      'e3aa212f2c02a4e035c17e2329aca12e' +
      '21d514b25466931c7d8f6a5aac84aa05' +
      '1ba30b396a0aac973d58e091'
    )
    const expectedTag = hex('5bc94fbc3221a5db94fae95ae7121a47')

    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain, aad)
    expect(ciphertext).to.deep.equal(expectedCt)
    expect(tag).to.deep.equal(expectedTag)
  })
})

describe('AES-GCM — round-trips', () => {
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv  = Buffer.from('U2FsdGVkX182re6L', 'base64')  // 12 bytes

  it('decrypt undoes encrypt for an arbitrary message', () => {
    const plain = Buffer.from('mensagem de comprimento qualquer')
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    const recovered = gcmDecrypt(encrypt(key), iv, ciphertext, tag)
    expect(recovered).to.deep.equal(plain)
  })

  it('round-trips with AAD', () => {
    const plain = Buffer.from('payload secreto')
    const aad = Buffer.from('cabeçalho autenticado mas nao cifrado')
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain, aad)
    const recovered = gcmDecrypt(encrypt(key), iv, ciphertext, tag, aad)
    expect(recovered.toString('utf8')).to.equal('payload secreto')
  })

  it('handles empty plaintext correctly', () => {
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, Buffer.alloc(0))
    expect(ciphertext.length).to.equal(0)
    const recovered = gcmDecrypt(encrypt(key), iv, ciphertext, tag)
    expect(recovered).to.deep.equal(Buffer.alloc(0))
  })
})

describe('AES-GCM — authentication', () => {
  const key = Buffer.from('DxVxyUfZ6FkMt63Wr39nmA==', 'base64')
  const iv  = Buffer.from('U2FsdGVkX182re6L', 'base64')
  const plain = Buffer.from('texto plano qualquer')

  it('rejects tampered ciphertext', () => {
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    const tampered = Buffer.from(ciphertext)
    tampered[0] = (tampered[0] ?? 0) ^ 0x01
    expect(() => gcmDecrypt(encrypt(key), iv, tampered, tag)).to.throw(GcmAuthError)
  })

  it('rejects tampered tag', () => {
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    const tampered = Buffer.from(tag)
    tampered[0] = (tampered[0] ?? 0) ^ 0x01
    expect(() => gcmDecrypt(encrypt(key), iv, ciphertext, tampered)).to.throw(GcmAuthError)
  })

  it('rejects tampered AAD', () => {
    const aad = Buffer.from('header')
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain, aad)
    const badAad = Buffer.from('Header')  // case change
    expect(() => gcmDecrypt(encrypt(key), iv, ciphertext, tag, badAad)).to.throw(GcmAuthError)
  })

  it('rejects wrong key', () => {
    const { ciphertext, tag } = gcmEncrypt(encrypt(key), iv, plain)
    const wrongKey = Buffer.alloc(16, 0xaa)
    expect(() => gcmDecrypt(encrypt(wrongKey), iv, ciphertext, tag)).to.throw(GcmAuthError)
  })
})

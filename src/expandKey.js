import subBytes from './steps/subBytes'
import addRoundKey from './steps/addRoundKey'

const rcon = [0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a]

const rotWord = word => [...word.slice(1,4), word[0]]
const subWord = subBytes
const xorRcon = (word, i) => [ rcon[i] ^ word[0], ...word.slice(1) ]

const keySchedule = (word, i) => xorRcon(subWord(rotWord(word)), i)

const lastWords = (word, behind) => word.slice(-behind*4).slice(0, 4)

const group = (arr, size) =>
  arr.reduce((a,b,i,g) =>
    !(i % size) ? (a.push(g.slice(i, i + size)), a) : a, [])

export default key => {
  let tmp, words = [...key]

  for(let i = 4; i < 44; i++) {
    tmp = lastWords(words, 1)
    if(i % 4 === 0) tmp = keySchedule(tmp, i/4)

    words = [...words, ...addRoundKey(lastWords(words, 4), tmp)]
  }
  
  return group(words, key.length)
}

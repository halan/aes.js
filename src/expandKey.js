import subBytes from './steps/subBytes'
import { xor, group } from './utils'

const rcon = [0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a]

const WORD_SIZE = 4
const ROUNDS = 10

const rotWord = word => [...word.slice(-(WORD_SIZE-1)), word[0]]

const subWord = subBytes

const xorRcon = (word, i) => [ rcon[i] ^ word[0], ...word.slice(1) ]

const keySchedule = (word, i) => xorRcon(subWord(rotWord(word)), i)

const lastWords = (word, behind) => word.slice(-behind*WORD_SIZE).slice(0, WORD_SIZE)

// # IMPROVEME
// 
// I want to avoid the `let` and the `for` here
// 
export default key => {
  let tmp, words = [...key]

  for(let i = WORD_SIZE; i < WORD_SIZE*(ROUNDS+1); i++) {
    tmp = lastWords(words, 1)
    if(i % WORD_SIZE === 0) tmp = keySchedule(tmp, i/WORD_SIZE)

    words = [...words, ...xor(lastWords(words, WORD_SIZE), tmp)]
  }
  
  return group(words, key.length)
}

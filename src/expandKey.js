import subBytes from './steps/subBytes'
import { xor, group } from './utils'

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

const WORDS_IN_A_KEY = 4

const WORD_SIZE = 4

const rotWord = word => [...word.slice(-(WORD_SIZE-1)), word[0]]

const subWord = subBytes

const xorFirstByte = (word, value) => [ value ^ word[0], ...word.slice(1) ]

const keyScheduleCore = (word, rcon) => xorFirstByte(subWord(rotWord(word)), rcon)

const lastWord = (arr) => arr.slice(-WORD_SIZE)

const generate = (key, rcon) => {
  const base = keyScheduleCore(lastWord(key), rcon)
  const words = group(key, WORDS_IN_A_KEY)

  return words.reduce( (k, word) => (
    [...k, ...xor(word, k.length ? lastWord(k) : base )]
  ), [])
}

export default key => (
  RCON.reduce( (keys, rcon) => {
    const [last] = [...keys].reverse()
    const current = generate(last, rcon)

    return [...keys, current]
  }, [key] )
)

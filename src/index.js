import { firstRound, middleRound, lastRound } from './steps'
import { isFirst, isLast } from './utils'

import expandKey from './expandKey'

const reducer = ({ keys, buffer }, key) => {
  if( isFirst(keys, key) )
    return { keys, buffer: firstRound(buffer, key) }

  else if( isLast(keys, key) )
    return { keys, buffer: lastRound(buffer, key) }

  return { keys, buffer: middleRound(buffer, key) }
}

const AES = (buffer, key) => {
  const keys = expandKey(key)

  return new Uint8Array(
    keys.reduce(reducer, { keys, buffer }).buffer
  )
}

export default AES

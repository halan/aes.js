
const pksc7 = target => input => {
  const inputBuffer = Buffer.from(input)
  const padLength = (target - inputBuffer.length % target || target)

  return Buffer.from([
    ...inputBuffer,
    ...Buffer.from(Array(padLength).fill(padLength))
  ])
}

const pksc7Inv = input => {
  const inputBuffer = Buffer.from(input)
  const size = inputBuffer[inputBuffer.length-1]

  return inputBuffer.slice(0, -size)
}

module.exports = { pksc7, pksc7Inv }

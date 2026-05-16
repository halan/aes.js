// Benchmark cruzado: TS puro vs WASM (Rust) vs `node:crypto` (AES-NI).
//
// Comparação ilustrativa do custo de uma implementação didática contra uma
// que aproveita instruções de hardware. Rode com `npm run bench`.
//
// Pré-requisito para a coluna WASM: `npm run build:wasm`.

import { performance } from 'node:perf_hooks'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import crypto from 'node:crypto'

import { encrypt as aesEncrypt } from '#aes'
import { cbc } from '#opModes'
import { gcmEncrypt } from '#gcm'

const __dirname = dirname(fileURLToPath(import.meta.url))
const wasmPath = resolve(__dirname, '..', 'rust', 'pkg-node', 'aes_rs.js')

const KEY  = Buffer.alloc(16, 0x42)
const IV   = Buffer.alloc(16, 0x21)
const IV96 = Buffer.alloc(12, 0x21)

interface Bench {
  label: string
  fn: () => void
}

interface Result {
  label: string
  minMs: number
  medianMs: number
  mbPerSec: number
}

function timeOnce(fn: () => void): number {
  const t0 = performance.now()
  fn()
  return performance.now() - t0
}

function run(label: string, fn: () => void, payloadBytes: number, iters: number): Result {
  // warmup
  for (let i = 0; i < 3; i++) fn()
  const samples: number[] = []
  for (let i = 0; i < iters; i++) samples.push(timeOnce(fn))
  samples.sort((a, b) => a - b)
  const minMs = samples[0]!
  const medianMs = samples[Math.floor(iters / 2)]!
  const mbPerSec = (payloadBytes / 1_000_000) / (medianMs / 1000)
  return { label, minMs, medianMs, mbPerSec }
}

function printTable(title: string, results: Result[]) {
  console.log(`\n${title}`)
  console.log('─'.repeat(70))
  console.log(`${'implementação'.padEnd(28)} ${'min (ms)'.padStart(12)} ${'median (ms)'.padStart(13)} ${'MB/s'.padStart(11)}`)
  console.log('─'.repeat(70))
  for (const r of results) {
    console.log(`${r.label.padEnd(28)} ${r.minMs.toFixed(2).padStart(12)} ${r.medianMs.toFixed(2).padStart(13)} ${r.mbPerSec.toFixed(2).padStart(11)}`)
  }
}

async function maybeLoadWasm(): Promise<((key: Buffer) => { cbcEncrypt: (iv: Buffer, p: Buffer) => Uint8Array, gcmEncrypt: (iv: Buffer, p: Buffer, aad: Uint8Array) => Uint8Array }) | null> {
  if (!existsSync(wasmPath)) return null
  const mod = await import(wasmPath) as { AesCipher: new (k: Uint8Array) => {
    cbcEncrypt: (iv: Buffer, p: Buffer) => Uint8Array
    gcmEncrypt: (iv: Buffer, p: Buffer, aad: Uint8Array) => Uint8Array
  } }
  return (key) => new mod.AesCipher(key)
}

const wasmCipherFactory = await maybeLoadWasm()
if (!wasmCipherFactory) {
  console.log('(WASM não disponível — rode `npm run build:wasm` para incluir a coluna Rust→WASM)')
}

// === CBC ===

for (const size of [64, 1024, 16 * 1024]) {
  const data = Buffer.alloc(size, 0xab)
  const iters = size >= 16 * 1024 ? 10 : 50
  const results: Result[] = []

  results.push(run('TS (puro)', () => { cbc(aesEncrypt(KEY))(IV)(data) }, size, iters))

  if (wasmCipherFactory) {
    const wc = wasmCipherFactory(KEY)
    results.push(run('Rust→WASM', () => { wc.cbcEncrypt(IV, data) }, size, iters))
  }

  results.push(run('node:crypto (AES-NI)', () => {
    const c = crypto.createCipheriv('aes-128-cbc', KEY, IV)
    c.update(data)
    c.final()
  }, size, iters))

  printTable(`AES-128-CBC encrypt — ${size} bytes`, results)
}

// === GCM ===

for (const size of [64, 1024, 16 * 1024]) {
  const data = Buffer.alloc(size, 0xab)
  const iters = size >= 16 * 1024 ? 10 : 50
  const results: Result[] = []

  results.push(run('TS (puro)', () => { gcmEncrypt(aesEncrypt(KEY), IV96, data) }, size, iters))

  if (wasmCipherFactory) {
    const wc = wasmCipherFactory(KEY)
    const emptyAad = new Uint8Array(0)
    results.push(run('Rust→WASM', () => { wc.gcmEncrypt(IV96, data, emptyAad) }, size, iters))
  }

  results.push(run('node:crypto (AES-NI)', () => {
    const c = crypto.createCipheriv('aes-128-gcm', KEY, IV96)
    c.update(data)
    c.final()
    c.getAuthTag()
  }, size, iters))

  printTable(`AES-128-GCM encrypt — ${size} bytes`, results)
}

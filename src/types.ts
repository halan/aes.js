// ## Tipos compartilhados
//
// O AES opera sobre bytes (números no intervalo `[0, 255]`) organizados em
// unidades fixas: words de 4 bytes, blocks/keys de 16 bytes, e o key schedule
// resulta em 11 round keys. Os tipos abaixo deixam essas dimensões explícitas
// onde ajuda — sem tornar a vida miserável onde TS perderia tuplaridade
// (e.g. `Array.prototype.map` sempre devolve `Byte[]`, não a tupla original).

export type Byte = number

// `Bytes` é o tipo "frouxo" usado dentro do pipeline. O comprimento esperado
// (4 para word, 16 para block) é uma convenção verificada em tempo de execução
// — pelo `xor` (que rejeita tamanhos divergentes) e pela validação no boundary.
export type Bytes = readonly Byte[]

// `BlockLike` aceita qualquer sequência de bytes indexável e iterável — `Buffer`,
// `Uint8Array` ou um array regular. As funções públicas convertem para `Block`
// (= `Byte[]`) no boundary via `Array.from`, mantendo o pipeline interno em um
// só formato. Sem isso, `Buffer.prototype.map` retornaria `Uint8Array` e o tipo
// `readonly Byte[]` exigiria casts em quase todo lugar.
export type BlockLike = ArrayLike<Byte> & Iterable<Byte>

// `Key` é o tipo de entrada das funções de alto nível — aceita qualquer
// `BlockLike`. A validação de comprimento (16 bytes para AES-128) acontece
// em runtime em `expandKey`.
export type Key = BlockLike

export type Word = Bytes   // length === 4 por convenção
export type Block = Bytes  // length === 16 por convenção (canônico interno: number[])

// O conjunto de round keys tem cardinalidade fixa: a chave original mais 10
// derivadas. Aqui a tupla agrega valor de fato: `head`/`last`/`middle` ganham
// não-vacuidade no nível de tipo.
export type RoundKeys = readonly [
  Block, Block, Block, Block, Block, Block,
  Block, Block, Block, Block, Block,
]

// Permutação fixa de 16 índices usada por `shiftRows`. A tupla garante que
// permutações construídas a partir de literais tenham exatamente 16 posições.
export type Permutation16 = readonly [
  number, number, number, number,
  number, number, number, number,
  number, number, number, number,
  number, number, number, number,
]

// Tabela de lookup de 256 bytes (S-box, S-box inversa, tabelas Galois G2/G3/G9/...).
// O comprimento exato (256) é convenção; uma tupla literal aqui só pioraria a
// experiência no editor.
export type LookupTable = Bytes

// Entrada aceita pelas APIs públicas — string (interpretada como UTF-8),
// Buffer/Uint8Array, ou um array de bytes. Convertemos para `Byte[]` logo na
// fronteira para que o pipeline interno opere sempre sobre arrays planos.
export type ByteInput = string | Uint8Array | readonly Byte[]

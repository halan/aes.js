# aes-es6 / aes-rs

Implementação didática do AES em **TypeScript** e **Rust**, com modos de operação, padding, GCM, bridge WASM e benchmarks comparativos. Foco em clareza algorítmica e estilo funcional explícito — **não usar em produção**.

O código vive em três frentes que se espelham:

| Pasta | O que é |
|---|---|
| `src/` | Implementação principal em TypeScript (ESM, tipos estreitos via `tsc --strict`) |
| `rust/` | Porta em Rust com const generics; suporta AES-128/192/256 |
| `rust/src/wasm.rs` | Ponte `wasm-bindgen` que expõe o lado Rust ao TS |
| `bench/` | Harness comparando TS puro × WASM × `node:crypto` (AES-NI) |

### Comandos

```bash
npm test                 # 61 testes TS (NIST FIPS-197, GCM SP 800-38D, padding, etc.)
npm run typecheck        # tsc estrito
npm run build:wasm       # gera rust/pkg-node/ via wasm-pack
npm run bench            # comparativo TS / WASM / node:crypto

cargo test --manifest-path rust/Cargo.toml          # 28 testes Rust
cargo bench --manifest-path rust/Cargo.toml         # criterion
```

---

# Aula: AES (Advanced Encryption Standard)

Esta seção é uma exposição teórica completa do AES. Quando o material reflete diretamente nosso código, indicamos o arquivo.

## 1. Contexto

### 1.1. Cifras simétricas

Existem dois grandes grupos de criptografia moderna:

- **Simétrica**: a mesma chave cifra e decifra. Rápida, usada para volume de dados. AES é o padrão.
- **Assimétrica (chave pública)**: chaves diferentes para cifrar e decifrar. Lenta, usada para troca de chaves e assinaturas. RSA, ECC.

Quase todo tráfego de internet hoje (HTTPS, SSH, Signal) usa criptografia assimétrica apenas para negociar uma chave simétrica; o conteúdo de fato é cifrado com AES (ou ChaCha20).

### 1.2. Antes do AES: DES

Em 1977, o NIST adotou o DES como padrão. Cifra de bloco, 64 bits de bloco, 56 bits de chave efetiva. Em 1998, a EFF construiu um *DES Cracker* por US$ 250 mil que quebrava DES em ~56 horas via busca exaustiva.

O NIST anunciou em 1997 um concurso público para o substituto. Critérios: segurança contra todos os ataques conhecidos, performance, simplicidade, flexibilidade.

### 1.3. Rijndael → AES

15 candidatos foram submetidos. Em 2000, o NIST escolheu **Rijndael**, dos belgas Joan Daemen e Vincent Rijmen. Em 2001 virou FIPS-197.

O Rijndael original suporta blocos de 128/192/256 bits e chaves de 128/192/256 bits — 9 combinações. O AES padronizou bloco de 128 bits e chaves de 128/192/256 bits — três variantes:

| Variante | Chave (bits) | Rounds |
|---|---|---|
| AES-128 | 128 | 10 |
| AES-192 | 192 | 12 |
| AES-256 | 256 | 14 |

No código Rust, isto aparece como `Aes<const NRK: usize>` em `rust/src/aes/mod.rs`, com `NRK` = round_keys = rounds + 1.

---

## 2. Cifra de bloco: o conceito

Uma **cifra de bloco** é uma família de permutações pseudo-aleatórias sobre blocos de tamanho fixo. Para AES:

```
E : {0,1}^k × {0,1}^128 → {0,1}^128
```

Onde `k` é o tamanho da chave (128, 192 ou 256). Para uma chave fixa, `E_K` é uma bijeção: cada bloco de 128 bits de plaintext mapeia para um único bloco de ciphertext, e vice-versa via `D_K`.

A propriedade que se exige: para um adversário sem a chave, `E_K` deve ser computacionalmente indistinguível de uma permutação aleatória uniformemente escolhida.

**Observação crítica**: AES sozinho é "só" uma permutação de blocos de 128 bits. Para cifrar mensagens reais (que têm tamanho variável), precisamos de **modos de operação**. Voltaremos a isso.

---

## 3. Fundamento matemático: GF(2^8)

Esta é a parte que mais confunde quem encontra AES pela primeira vez. Quase todo o algoritmo opera em **corpos finitos**.

### 3.1. O que é um corpo

Um corpo é um conjunto onde você pode somar, subtrair, multiplicar e dividir (exceto por zero) e os resultados ficam no conjunto. Os racionais, reais e complexos são corpos infinitos.

Existem corpos finitos. Para todo primo `p` e inteiro `n ≥ 1`, existe um único corpo finito de tamanho `p^n`, denotado `GF(p^n)` (Galois Field).

AES vive em `GF(2^8)` — 256 elementos, um para cada byte.

### 3.2. Por que GF(2^8) e não Z/256

Você pode se perguntar: por que não usar aritmética módulo 256 (`Z/256Z`)? Resposta: `Z/256Z` não é um corpo. O 2 não tem inverso multiplicativo módulo 256 (porque 2 divide 256). Sem divisão, não dá pra construir uma S-Box invertível com a estrutura algébrica desejada.

GF(2^8) tem 256 elementos *e* permite divisão, porque é construído como polinômios módulo um polinômio irredutível.

### 3.3. Como GF(2^8) funciona

Cada byte é um polinômio de grau ≤ 7 sobre GF(2). O byte `0x53 = 0101 0011` representa:

```
x^6 + x^4 + x + 1
```

(coeficientes são os bits, do mais significativo ao menos).

**Soma** é XOR byte-a-byte. Coeficientes são em GF(2), então `1 + 1 = 0`:

```
(x^6 + x^4) + (x^4 + x^2) = x^6 + x^2   (o x^4 cancelou)
```

Em código: `a ^ b` para bytes. É por isso que `addRoundKey` é só XOR.

**Multiplicação** é multiplicação polinomial seguida de redução módulo o polinômio irredutível:

```
m(x) = x^8 + x^4 + x^3 + x + 1
```

Em hex isso é `0x11b`. AES usa especificamente esse polinômio.

Multiplicar `0x53` por `0xCA`:
1. Multiplicar como polinômios → polinômio de grau até 14
2. Reduzir módulo `m(x)` → polinômio de grau ≤ 7 → cabe num byte

A multiplicação por 2 (`xtime`) tem uma forma fechada simples:

```
xtime(b) = (b << 1)         se o bit alto era 0
xtime(b) = (b << 1) ^ 0x1b  se o bit alto era 1
```

Isso porque multiplicar por `x` é shift-left, e se "estoura" para grau 8 reduzimos subtraindo `m(x)` — em GF(2), subtrair é XORar, e os 8 bits baixos de `m(x)` são `0x1b`.

### 3.4. Onde isto entra no AES

Quatro lugares:
- **S-Box** é definida via inverso multiplicativo em GF(2^8) seguido de uma transformação afim
- **MixColumns** multiplica colunas por uma matriz fixa onde as entradas são `02`, `01`, `03` — multiplicações em GF(2^8)
- **Key schedule** usa a S-Box e constantes `RCON` que são potências de 2 em GF(2^8)
- **GHASH** (autenticação do GCM) é multiplicação em GF(2^128) — um corpo análogo, polinômio de grau 128

No nosso código, as tabelas `G2`, `G3`, `G9`, `G11`, `G13`, `G14` em `src/aes/rounds/mixColumns.ts` (e `mix_columns.rs`) são essas multiplicações pré-calculadas. Por exemplo `G2[0x53]` = 2 · 0x53 em GF(2^8).

---

## 4. O estado AES

O AES processa blocos de 128 bits, mas internamente organiza esses 16 bytes numa matriz **4×4 column-major**:

```
s₀₀  s₀₁  s₀₂  s₀₃
s₁₀  s₁₁  s₁₂  s₁₃
s₂₀  s₂₁  s₂₂  s₂₃
s₃₀  s₃₁  s₃₂  s₃₃
```

Os bytes entram coluna a coluna: o input `b₀ b₁ b₂ ... b₁₅` vira:

```
b₀   b₄   b₈   b₁₂
b₁   b₅   b₉   b₁₃
b₂   b₆   b₁₀  b₁₄
b₃   b₇   b₁₁  b₁₅
```

Na nossa implementação representamos isso linearmente — `Block = [u8; 16]` em Rust, `readonly Byte[]` (length 16) em TS. A "coluna" é um chunk de 4 bytes consecutivos (a `Word`).

Por que matriz e não array linear conceitualmente? Porque três das quatro operações (ShiftRows, MixColumns) fazem mais sentido visualmente em 2D.

---

## 5. As quatro etapas

Cada round (com pequenas variações) aplica quatro transformações ao estado. Vamos uma por uma.

### 5.1. SubBytes — substituição não-linear

```
state[i] ← SBOX[state[i]]
```

Para cada byte, substitui pelo valor em uma tabela de 256 entradas.

A S-Box é definida assim:
1. Tomar o inverso multiplicativo em GF(2^8) (mapeando `0 ↦ 0` para evitar divisão por zero)
2. Aplicar uma transformação afim sobre GF(2):

```
b'ᵢ = bᵢ ⊕ b₍ᵢ₊₄₎ ⊕ b₍ᵢ₊₅₎ ⊕ b₍ᵢ₊₆₎ ⊕ b₍ᵢ₊₇₎ ⊕ cᵢ
```

Onde `c = 0x63` é uma constante fixa e os índices são mod 8.

**Por que essa construção?** A não-linearidade da S-Box é a principal defesa contra criptanálise diferencial e linear. O inverso multiplicativo é "muito não-linear" em GF(2). A transformação afim quebra a estrutura algébrica restante (para evitar ataques baseados em propriedades de corpo finito) e elimina pontos fixos da função inverso (não há `x` tal que `SBOX(x) = x`).

No nosso código:

```ts
// src/aes/rounds/subBytes.ts
const sub = (table: LookupTable) => (buffer: readonly Byte[]): Byte[] =>
  buffer.map((b) => table[b])
```

A elegância oculta: como o inverso é uma operação algébrica simétrica, a S-Box inversa é só "inverter a afim, depois inverter o inverso" — e isso é a `SBOX_INV` que também guardamos como tabela.

### 5.2. ShiftRows — difusão por permutação

Rotaciona cada linha do estado por um offset diferente:

```
Linha 0: shift 0 (não mexe)
Linha 1: shift 1 à esquerda
Linha 2: shift 2 à esquerda
Linha 3: shift 3 à esquerda
```

Visualmente:

```
a  b  c  d           a  b  c  d
e  f  g  h     →     f  g  h  e
i  j  k  l           k  l  i  j
m  n  o  p           p  m  n  o
```

**Por que?** SubBytes é byte-a-byte — uma mudança num byte do plaintext só afeta um byte do estado. ShiftRows espalha essa mudança lateralmente: o byte que estava na coluna 0 agora pode estar em qualquer coluna. Sem isso, cada coluna evoluiria independente e o cifrador seria trivialmente quebrável.

Como o layout do estado é column-major mas a operação age nas linhas, em código a permutação fica como uma tabela fixa de 16 índices:

```rust
// rust/src/aes/rounds/shift_rows.rs
const SHIFT_ROWS: [usize; 16] = [
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11,
];
```

A operação é declarativa: `permute(&SHIFT_ROWS, &state)`.

### 5.3. MixColumns — difusão por transformação linear

Cada coluna (4 bytes) é multiplicada por uma matriz fixa em GF(2^8):

```
| 02 03 01 01 |   | a₀ |
| 01 02 03 01 | · | a₁ |
| 01 01 02 03 |   | a₂ |
| 03 01 01 02 |   | a₃ |
```

A multiplicação é em GF(2^8), e a soma é XOR.

**Por que essa matriz?** Tem uma propriedade chamada *MDS (Maximum Distance Separable)*: qualquer mudança num byte da entrada altera todos os 4 bytes da saída. Combinado com ShiftRows, isso garante difusão completa em 2 rounds — qualquer bit do plaintext influencia qualquer bit do ciphertext.

Em código, em vez de fazer a multiplicação em GF(2^8) on-the-fly, pré-calculamos tabelas `G2[b] = 2·b` e `G3[b] = 3·b`:

```ts
const mixCol = ([a0, a1, a2, a3]: Word): Byte[] => [
  g2(a0) ^ g3(a1) ^ a2    ^ a3,
  a0     ^ g2(a1) ^ g3(a2) ^ a3,
  a0     ^ a1     ^ g2(a2) ^ g3(a3),
  g3(a0) ^ a1     ^ a2     ^ g2(a3),
]
```

A inversa precisa de mais tabelas (`G9`, `G11`, `G13`, `G14`) porque a matriz inversa tem entradas mais complexas.

### 5.4. AddRoundKey — mistura com a chave

XOR byte-a-byte do estado com a round key:

```
state ← state ⊕ round_key
```

**Por que?** É a única operação onde a chave entra. Sem ela, AES seria uma função fixa — qualquer plaintext sempre produziria o mesmo ciphertext. Todo o segredo está aqui.

Como XOR é involutivo, `AddRoundKey` é seu próprio inverso. No nosso código:

```ts
// src/aes/rounds/addRoundKey.ts
export const addRoundKey: (key: Block) => (state: Block) => Block = xor
```

É literalmente um alias.

---

## 6. Key Schedule — expansão de chave

AES não usa a chave original em todos os rounds — cada round usa uma *round key* derivada. Para AES-128 com 10 rounds, precisamos de **11 round keys** (uma para o pré-whitening antes do primeiro round + uma por round).

A chave original ocupa as 4 primeiras words. As demais são geradas por:

```
for i in 4..44:
    temp = W[i-1]
    if i % 4 == 0:
        temp = subWord(rotWord(temp)) ⊕ RCON[i/4]
    W[i] = W[i-4] ⊕ temp
```

Onde:
- `subWord`: aplica a S-Box em cada byte da word
- `rotWord`: rotaciona `[a,b,c,d] → [b,c,d,a]`
- `RCON[i]` é uma constante que vale `x^i` em GF(2^8) (a potência aumenta a cada uso)

**Por que essa estrutura?** Três propriedades desejáveis:
1. **Não-linearidade**: a S-Box impede que round keys sejam combinações lineares simples da chave original
2. **Diferenciação entre rounds**: RCON garante que round keys distintas são diferentes mesmo se a chave tiver simetria
3. **Reversibilidade**: dada qualquer round key, é possível derivar a chave original (em ataques *related-key*, isso seria ruim, mas a S-Box dificulta na prática)

Para AES-192 e AES-256 o algoritmo é o mesmo padrão mas com `Nk` (tamanho da chave em words) maior, e AES-256 tem uma sutileza extra: aplica `subWord` adicional a cada 4 words *intermediárias*.

No nosso código, isso aparece numa única função genérica:

```rust
// rust/src/aes/expand_key.rs
for i in nk..total_words {
    let mut temp = words[i - 1];
    if i.is_multiple_of(nk) {
        temp = sub_word(rot_word(temp));
        temp[0] ^= RCON[i / nk];
    } else if nk > 6 && i % nk == 4 {
        // AES-256 only
        temp = sub_word(temp);
    }
    words.push(xor(&words[i - nk], &temp));
}
```

Um único `if/else if` cobre as três variantes.

---

## 7. A estrutura completa

Juntando tudo, AES-128 cifra um bloco assim:

```
state = plaintext
state = AddRoundKey(state, K₀)            // pré-whitening
for r in 1..10:
    state = SubBytes(state)
    state = ShiftRows(state)
    state = MixColumns(state)
    state = AddRoundKey(state, Kᵣ)
state = SubBytes(state)                    // último round
state = ShiftRows(state)
state = AddRoundKey(state, K₁₀)            // sem MixColumns
return state
```

**Por que o último round não tem MixColumns?** Para que o cifrador seja invertível na forma "espelho": a decifragem fica simétrica em estrutura. Sem essa omissão, o esquema funcionaria mas seria menos elegante de descrever.

No nosso código:

```rust
// rust/src/aes/mod.rs
pub fn encrypt(&self, state: Block) -> Block {
    let nr = NRK - 1;
    let state = first_round(&self.round_keys[0], state);
    let state = (1..nr).fold(state, |s, i| middle_round(&self.round_keys[i], s));
    last_round(&self.round_keys[nr], state)
}
```

Decifragem aplica as inversas em ordem reversa:

```
state = AddRoundKey(state, K₁₀)
state = ShiftRows⁻¹(state)
state = SubBytes⁻¹(state)
for r in 9..1:
    state = AddRoundKey(state, Kᵣ)
    state = MixColumns⁻¹(state)
    state = ShiftRows⁻¹(state)
    state = SubBytes⁻¹(state)
state = AddRoundKey(state, K₀)
return state
```

---

## 8. Modos de operação

Repetindo o ponto crucial: AES sozinho cifra exatamente 16 bytes. Mensagens reais têm tamanho variável. Daí os **modos de operação**.

### 8.1. ECB (Electronic CodeBook)

Cada bloco de plaintext é cifrado independentemente:

```
Cᵢ = E_K(Pᵢ)
```

**Por que é ruim**: blocos idênticos de plaintext geram blocos idênticos de ciphertext. Padrões visuais sobrevivem (a famosa imagem do "pinguim Tux cifrado em ECB" mostra isso). Determinístico — vaza igualdade.

Por isso nosso `ecb` e `ecb_encrypt` levam um comentário de aviso e ficam expostos apenas para fins didáticos.

### 8.2. CBC (Cipher Block Chaining)

Cada bloco de plaintext é XORado com o ciphertext do bloco anterior antes de ser cifrado:

```
C₀ = E_K(IV ⊕ P₀)
Cᵢ = E_K(Cᵢ₋₁ ⊕ Pᵢ)
```

O **IV** (Initialization Vector) substitui o "bloco anterior" que não existe no início. Para CBC, o IV deve ser **único e imprevisível** — reusar IV vaza igualdade de prefixos; IV previsível habilita ataques de plaintext escolhido (Vaudenay, BEAST).

Em FP, CBC encrypt é um `scanl` puro:

```ts
// src/opModes.ts
scanl(prev => block => encrypt(xor(prev)(block)))(iv)
```

Cada bloco cifrado vira o estado para o próximo passo.

CBC decrypt é diferente — o "estado" propagado é o bloco *cifrado* anterior (não o decifrado), e a saída é o plaintext:

```ts
mapAccumL(prev => block => [block, xor(prev)(decrypt(block))])(iv)
```

Este é o caso geral do `scanl`: estado e saída são tipos diferentes. Em Haskell se chama `mapAccumL`. Em Rust ambos usam `Iterator::scan`.

**Padding**: como o último bloco pode não ter 16 bytes, precisamos preencher. PKCS#7: completa com bytes cujo valor é o número de bytes adicionados. Se o input já é múltiplo de 16, adiciona um bloco inteiro de padding. Isso garante recuperação inequívoca.

**Limitação fundamental do CBC**: não autentica. Um atacante pode flipar bytes do IV ou de blocos anteriores e prever exatamente como o plaintext muda (atributo da estrutura XOR-then-cipher). Sem MAC, ciphertext é maleável.

### 8.3. CTR (Counter)

Em vez de cifrar o plaintext, CTR cifra um *contador* e XORa o resultado com o plaintext:

```
keystreamᵢ = E_K(IV || counter_i)
Cᵢ = Pᵢ ⊕ keystreamᵢ
```

Vantagens:
- Paralelizável (cada bloco independe dos outros)
- Não precisa de padding (XOR com a partial keystream)
- Decifragem = cifragem (basta gerar a mesma keystream)

Desvantagem fundamental: **se você reusar o contador inicial com a mesma chave**, dois ciphertexts diferentes XORam para revelar `P₁ ⊕ P₂` — o que normalmente é suficiente para recuperar ambos.

CTR também não autentica sozinho — mas combinado com GHASH, vira **GCM**.

### 8.4. GCM (Galois/Counter Mode) — AEAD

GCM = CTR + GHASH. Resolve o problema fundamental que ficamos arrastando: **autenticação**.

Procedimento:
1. `H = E_K(0^128)` — chave de hash derivada da chave AES
2. `J₀` = bloco inicial de contador (para IV de 96 bits: `IV || 00 00 00 01`)
3. **Ciphertext**: CTR com contador começando em `inc(J₀)`
4. **Tag**: GHASH sobre `AAD || ciphertext || lens` cifrado com `J₀`

GHASH é um polinômio hash:

```
y₀ = 0
yᵢ = (yᵢ₋₁ ⊕ blockᵢ) · H em GF(2^128)
```

A "multiplicação" é em GF(2^128) com polinômio `x^128 + x^7 + x^2 + x + 1`. Mesma estrutura de GF(2^8), só num corpo maior.

O tag final é `E_K(J₀) ⊕ GHASH(...)` — uma "criptografia" do hash, o que evita ataques que explorariam apenas o GHASH.

**AAD (Associated Data)**: dado autenticado mas não cifrado. Útil para headers que precisam ficar legíveis mas não podem ser modificados sem detecção.

No nosso `src/gcm.ts` e `rust/src/gcm.rs`, vemos esse fluxo. Verificação do tag é em **tempo constante** — uma comparação byte-a-byte sem curto-circuito. Curto-circuitar vazaria timing sobre quais bytes batem, oráculo suficiente para forjar tags.

**GCM é AEAD** (Authenticated Encryption with Associated Data). É o que se usa em produção: TLS 1.3, SSH moderno, mensageria.

---

## 9. Segurança: o que pode dar errado

### 9.1. Padding oracle

Se você usa CBC com PKCS#7 e a função de decifragem distingue "padding inválido" de "padding válido mas conteúdo errado" *de forma observável* (timing, mensagens de erro, comportamento downstream), um atacante pode forjar plaintext byte-a-byte modificando o IV/ciphertext e observando reações.

Defesa: usar MAC (ou AEAD como GCM). Validar autenticidade *antes* de validar padding. Comparar em tempo constante.

No nosso `pksc7_inv` adicionamos validação explícita; mas isso só fecha *uma* porta, não o oráculo de verdade — que requer ausência de canais laterais.

### 9.2. Cache timing

A S-Box é uma tabela de 256 bytes acessada por índices dependentes da chave. Em hardware com cache compartilhado (FaaS, containers, máquinas multi-tenant), um atacante pode medir tempos de acesso ao cache para inferir quais entradas da S-Box foram tocadas, e dali deduzir bytes da chave (ataques Bernstein 2005, Osvik–Shamir–Tromer 2006).

Defesas práticas:
- **AES-NI**: instruções de hardware (`AESENC`, `AESDEC`) que executam o round inteiro em tempo constante. É o que `node:crypto` usa, e dá os ~1.2 GB/s do nosso benchmark.
- **Bitsliced AES**: representa o estado de forma "bit-paralela" para que operações sejam constant-time. Lento mas seguro em SW.

Nossa implementação didática não tem nenhuma das duas.

### 9.3. Reuso de IV/nonce

**CBC**: IV previsível habilita ataques de plaintext escolhido. Deve ser imprevisível.
**CTR/GCM**: reuso de contador inicial com mesma chave é catastrófico. Para GCM com IV de 96 bits, uma única reutilização compromete a confidencialidade *e* a autenticidade do par.

Por isso GCM tem limite formal de mensagens por chave: ~2^32 mensagens com IVs de 96 bits aleatórios antes da probabilidade de colisão virar significativa.

### 9.4. Tamanho de dados em GCM

Como o contador incrementa apenas os 32 bits finais, ele dá a volta em 2^32 blocos = ~64 GiB. Após isso, a keystream se repete — desastre. NIST limita oficialmente a (2^39 − 256) bits = ~64 GiB de plaintext por chamada GCM.

### 9.5. Modelos de ataque

A literatura formaliza ataques por *capacidade* do adversário:

- **IND-CPA** (chosen-plaintext): adversário pode pedir cifrações arbitrárias. CBC com IV aleatório oferece isso. ECB não.
- **IND-CCA** (chosen-ciphertext): adversário também pode pedir decifrações. CBC sem MAC é vulnerável aqui (via padding oracle). GCM resiste — qualquer ciphertext forjado é rejeitado pelo tag.
- **AEAD security**: confidencialidade + integridade + integridade de AAD. GCM oferece formalmente.

---

## 10. Visão de conjunto

Voltando atrás, dá pra ver o AES como uma rede *substitution-permutation* (SPN) bem desenhada:

- **Substituição não-linear** (SubBytes): defende contra criptanálise linear/diferencial
- **Difusão local** (MixColumns) + **difusão larga** (ShiftRows): garante que mudanças se espalham rapidamente
- **Mistura com chave** (AddRoundKey): o único lugar onde o segredo entra; a única coisa que reverte a deterministicidade

Cada uma dessas operações é simples isoladamente; a segurança emerge da composição em 10/12/14 rounds e da expansão de chave.

Aplicado num único bloco de 16 bytes, AES é uma permutação pseudo-aleatória. Para mensagens reais, **modos de operação** dão semântica:

- **ECB**: nunca usar
- **CBC**: confidencialidade IND-CPA, *não* autentica (não usar sem MAC)
- **CTR**: confidencialidade IND-CPA, *não* autentica
- **GCM**: AEAD — confidencialidade + autenticidade + AAD. Padrão moderno.

E embaixo de tudo, **GF(2^8)** (corpo finito de bytes) e **GF(2^128)** (corpo finito de blocos para GHASH) são a álgebra que dá às operações suas propriedades desejáveis (invertibilidade da S-Box, MDS da MixColumns, "comportamento aleatório" do GHASH).

---

## 11. O que não vimos

Para uma exposição didática completa em criptografia simétrica de bloco, ficaram de fora:

- **Criptanálise diferencial e linear** (a justificativa formal da S-Box e do número de rounds)
- **Outros modos**: OCB, CCM, SIV, XTS (este último para criptografia de disco)
- **AEAD modernos não-AES**: ChaCha20-Poly1305 — design diferente, sem corpos finitos, mais simples de implementar com tempo constante em SW
- **Pós-quantum**: AES sobrevive ao algoritmo de Grover apenas duplicando o tamanho da chave (AES-256 mantém ~128 bits de segurança contra computador quântico). Para criptografia assimétrica a história é outra.

---

# Aviso de segurança

Este código **não é recomendado para produção**. Foi escrito para ser legível e descritivo, não eficiente ou seguro. Limitações inerentes (mesmo após o hardening que adicionamos):

- **Side-channel exposure.** A S-Box e as tabelas de multiplicação de Galois tornam o tempo de execução dependente do dado. Em hardware compartilhado isso vaza material da chave via cache-timing. Mitigação real exige bitslicing ou AES de hardware (AES-NI / `crypto.subtle`) — nenhum dos dois sobreviveria ao propósito didático.
- **Performance.** Como mostra `npm run bench`, somos ~3000× mais lentos que `node:crypto` em CBC, e ~2800× mais lentos em GCM. A versão Rust→WASM fecha boa parte desse gap (130× sobre o TS puro) mas ainda deixa ~30× para AES-NI.
- **ECB é exposto mas inseguro.** Existe apenas por completude didática; jamais usar.
- **TypeScript: AES-128 apenas.** Chaves de outros tamanhos são rejeitadas. O lado Rust suporta AES-128/192/256 via `Aes<const NRK: usize>`.

Para uso real: `crypto.createCipheriv('aes-256-gcm', ...)` no Node, `crypto.subtle` no browser, `aes-gcm` ou `ring` em Rust.

---

# Referências

Originais e canônicos:
- **[FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)** — especificação do AES (NIST). Curta, ~50 páginas.
- **[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)** — modos de operação clássicos (ECB, CBC, CTR, CFB, OFB).
- **[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)** — GCM.
- **Daemen & Rijmen — "The Design of Rijndael"** — livro dos autores. Explica *por que* cada decisão foi tomada.

Pedagógicos:
- **Cryptography Engineering** (Ferguson, Schneier, Kohno).
- **[Boneh & Shoup — "A Graduate Course in Applied Cryptography"](https://toc.cryptobook.us/)** — gratuito online.
- **[movable-type.co.uk/scripts/aes.html](http://www.movable-type.co.uk/scripts/aes.html)** — walkthrough visual.

Implementações de referência usadas como consulta:
- [crypto-js](https://github.com/brix/crypto-js/blob/develop/src/aes.js)
- [tiny-AES128-C](https://github.com/kokke/tiny-AES128-C/blob/master/aes.c)
- [chrishulbert/crypto (Ruby)](https://github.com/chrishulbert/crypto/blob/master/ruby/ruby_aes.rb)

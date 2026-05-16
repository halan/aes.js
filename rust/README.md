# aes-rs

Porta em Rust da implementação didática de AES-128 que vive em [`../src`](../src) (TypeScript). Mesmo espírito — clareza acima de performance, comentários em pt-BR explicando o algoritmo — adaptada às idiomas do Rust.

## O que muda em relação ao TS

- **Tipos exatos no compile-time**. `Block = [u8; 16]`, `Word = [u8; 4]`, `RoundKeys = [Block; 11]`. Em TS isso era convenção verificada em runtime; aqui o compilador rejeita um `xor(&block, &word)` antes de você apertar enter.
- **Const generics**. `xor<const N: usize>` e `permute<const N: usize>` aceitam qualquer tamanho — desde que os dois argumentos tenham o mesmo. O `Error: mismatched lengths` da versão TS deixou de existir.
- **`Iterator::scan` no lugar do `scanl` artesanal**. CBC encrypt e expansão de chave caem diretamente nesse combinador da stdlib. CBC decrypt usa o mesmo `scan` com semântica de `mapAccumL` (estado ≠ saída).
- **`Result<_, PaddingError>` para padding**. A versão TS usava `throw`; em Rust o erro aparece no tipo da função, sem custo de runtime.
- **`trait BlockCipher`**. Modos de operação genéricos sobre qualquer cifrador. `Aes128` implementa o trait; outros podem ser plugados sem modificar `op_modes.rs`.

## Comandos

```bash
cargo test                          # 15 testes (NIST FIPS-197, round-trips, padding)
cargo clippy --all-targets         # configurado com clippy::pedantic
cargo doc --open                    # documentação navegável
```

## Avisos

Idênticos ao README principal: **não usar em produção**. Sem MAC, sem proteção contra cache-timing (S-Box e tabelas Galois são lookups dependentes do dado secreto). AES-128 apenas — outros tamanhos são intencionalmente rejeitados pelo sistema de tipos.

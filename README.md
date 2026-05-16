[Código comentado em português...](https://halan.github.io/aes-es6/index.html)

# Warning

This code is not recommended for use in production!
It was not written to be efficient or safe, only readable and descriptive for didactic purposes.

Specifically, even after recent hardening (input validation on key length, on XOR
operand sizes, and on PKCS#7 padding), the following cryptographic limitations
remain by design:

- **No authentication.** Neither CBC nor ECB attaches a MAC, so ciphertext is
  malleable. A real deployment needs an AEAD mode (e.g. AES-GCM) or
  encrypt-then-MAC.
- **Side-channel exposure.** The S-box and Galois-multiplication lookup tables
  make execution time data-dependent. On shared hardware this leaks key material
  via cache-timing attacks. Mitigation requires bitslicing or hardware AES
  (`crypto.subtle` / AES-NI), neither of which would survive the didactic goal.
- **ECB is exposed but unsafe.** It is exported only for completeness; do not
  use it.
- **AES-128 only.** Keys of any other length are rejected.

# References (AES)

- http://www.movable-type.co.uk/scripts/aes.html
- https://github.com/brix/crypto-js/blob/develop/src/aes.js
- https://github.com/kokke/tiny-AES128-C/blob/master/aes.c
- https://github.com/chrishulbert/crypto/blob/master/ruby/ruby_aes.rb
- Cryptography and Network Security: Principles and Practice (https://g.co/kgs/UUEmv7)

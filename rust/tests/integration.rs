//! Testes de integração espelhando o suite TS.
//!
//! Cobre:
//! - Vetores oficiais NIST FIPS-197 (apêndices B e C.1)
//! - Round-trip do cifrador de blocos
//! - ECB e CBC com plaintexts de tamanhos variados
//! - Validação de padding PKCS#7
//! - Detecção de tampering em CBC via padding
//! - Rejeição de chaves inválidas (garantida em compile-time, não testável)

use aes_rs::aes::expand_key::expand_key;
use aes_rs::padding::{pksc7, pksc7_inv, PaddingError};
use aes_rs::types::{Block, Byte, Key};
use aes_rs::{cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt, Aes128, Aes192, Aes256};

// === Vetores NIST FIPS-197 ===

#[test]
fn nist_fips197_appendix_b() {
    let key: Key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let plain: Block = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    let expected: Block = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
    ];

    let cipher = Aes128::new(&key);
    assert_eq!(cipher.encrypt(plain), expected);
    assert_eq!(cipher.decrypt(expected), plain);
}

#[test]
fn nist_fips197_appendix_c1() {
    let key: Key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let plain: Block = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected: Block = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    let cipher = Aes128::new(&key);
    assert_eq!(cipher.encrypt(plain), expected);
    assert_eq!(cipher.decrypt(expected), plain);
}

// === Vetores NIST FIPS-197 — AES-192 e AES-256 ===

#[test]
fn nist_fips197_appendix_c2_aes192() {
    let key: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let plain: Block = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected: Block = [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91,
    ];

    let cipher = Aes192::new(&key);
    assert_eq!(cipher.encrypt(plain), expected);
    assert_eq!(cipher.decrypt(expected), plain);
}

#[test]
fn nist_fips197_appendix_c3_aes256() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let plain: Block = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected: Block = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    let cipher = Aes256::new(&key);
    assert_eq!(cipher.encrypt(plain), expected);
    assert_eq!(cipher.decrypt(expected), plain);
}

#[test]
fn aes192_cbc_round_trip() {
    let key: [u8; 24] = [0xaa; 24];
    let iv: Block = [0xbb; 16];
    let cipher = Aes192::new(&key);
    let plain = b"AES-192 round trip!!!!";

    let ct = cbc_encrypt(&cipher, &iv, plain);
    let pt = cbc_decrypt(&cipher, &iv, &ct).unwrap();
    assert_eq!(pt, plain);
}

#[test]
fn aes256_cbc_round_trip() {
    let key: [u8; 32] = [0xcc; 32];
    let iv: Block = [0xdd; 16];
    let cipher = Aes256::new(&key);
    let plain = b"AES-256 round trip with a longer message";

    let ct = cbc_encrypt(&cipher, &iv, plain);
    let pt = cbc_decrypt(&cipher, &iv, &ct).unwrap();
    assert_eq!(pt, plain);
}

// === expand_key contra valores conhecidos ===

#[test]
fn expand_key_matches_known_schedule() {
    let key: Key = [
        15, 21, 113, 201, 71, 217, 232, 89, 12, 183, 173, 214, 175, 127, 103, 152,
    ];
    let expected: [Block; 11] = [
        [
            15, 21, 113, 201, 71, 217, 232, 89, 12, 183, 173, 214, 175, 127, 103, 152,
        ],
        [
            220, 144, 55, 176, 155, 73, 223, 233, 151, 254, 114, 63, 56, 129, 21, 167,
        ],
        [
            210, 201, 107, 183, 73, 128, 180, 94, 222, 126, 198, 97, 230, 255, 211, 198,
        ],
        [
            192, 175, 223, 57, 137, 47, 107, 103, 87, 81, 173, 6, 177, 174, 126, 192,
        ],
        [
            44, 92, 101, 241, 165, 115, 14, 150, 242, 34, 163, 144, 67, 140, 221, 80,
        ],
        [
            88, 157, 54, 235, 253, 238, 56, 125, 15, 204, 155, 237, 76, 64, 70, 189,
        ],
        [
            113, 199, 76, 194, 140, 41, 116, 191, 131, 229, 239, 82, 207, 165, 169, 239,
        ],
        [
            55, 20, 147, 72, 187, 61, 231, 247, 56, 216, 8, 165, 247, 125, 161, 74,
        ],
        [
            72, 38, 69, 32, 243, 27, 162, 215, 203, 195, 170, 114, 60, 190, 11, 56,
        ],
        [
            253, 13, 66, 203, 14, 22, 224, 28, 197, 213, 74, 110, 249, 107, 65, 86,
        ],
        [
            180, 142, 243, 82, 186, 152, 19, 78, 127, 77, 89, 32, 134, 38, 24, 118,
        ],
    ];
    assert_eq!(expand_key::<16, 11>(&key), expected);
}

// === CBC e ECB ===

const KEY: Key = [
    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98,
];
const IV: Block = [
    0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f, 0x7a, 0xad, 0xee, 0x8b, 0xc3, 0x9c, 0x0e, 0x65,
];

#[test]
fn cbc_round_trip_known_plaintext() {
    let plain = b"Hola mundo!!!!!!";
    let cipher = Aes128::new(&KEY);

    let ct = cbc_encrypt(&cipher, &IV, plain);
    let pt = cbc_decrypt(&cipher, &IV, &ct).expect("valid padding after round-trip");
    assert_eq!(pt, plain);
}

#[test]
fn ecb_round_trip_known_plaintext() {
    let plain = b"Hola mundo!!!!!!";
    let cipher = Aes128::new(&KEY);

    let ct = ecb_encrypt(&cipher, plain);
    let pt = ecb_decrypt(&cipher, &ct).expect("valid padding after round-trip");
    assert_eq!(pt, plain);
}

#[test]
fn cbc_round_trip_varied_sizes() {
    let cipher = Aes128::new(&KEY);
    let cases: &[&[u8]] = &[
        b"",
        b"short",
        b"fifteen bytes!!",
        b"sixteen bytes!!!",
        b"thirty-two bytes for two blocks!",
        b"this plaintext is longer than sixteen bytes",
    ];

    for plain in cases {
        let ct = cbc_encrypt(&cipher, &IV, plain);
        let pt = cbc_decrypt(&cipher, &IV, &ct).expect("valid padding");
        assert_eq!(pt, *plain, "CBC round-trip failed for {plain:?}");
    }
}

#[test]
fn ecb_round_trip_varied_sizes() {
    let cipher = Aes128::new(&KEY);
    let cases: &[&[u8]] = &[
        b"",
        b"short",
        b"fifteen bytes!!",
        b"sixteen bytes!!!",
        b"this plaintext is longer than sixteen bytes",
    ];

    for plain in cases {
        let ct = ecb_encrypt(&cipher, plain);
        let pt = ecb_decrypt(&cipher, &ct).expect("valid padding");
        assert_eq!(pt, *plain, "ECB round-trip failed for {plain:?}");
    }
}

// === Validação de padding ===

#[test]
fn pksc7_aligns_to_block_size() {
    let padded = pksc7(b"hello"); // 5 bytes -> 11 bytes of padding (value 11)
    assert_eq!(padded.len(), 16);
    assert!(padded[5..].iter().all(|&b| b == 11));
}

#[test]
fn pksc7_appends_full_block_when_aligned() {
    let padded = pksc7(b"sixteen bytes!!!"); // exactly aligned -> 16 bytes of padding (value 16)
    assert_eq!(padded.len(), 32);
    assert!(padded[16..].iter().all(|&b| b == 16));
}

#[test]
fn pksc7_round_trip() {
    let original: &[u8] = b"arbitrary message of any length";
    let padded = pksc7(original);
    assert_eq!(pksc7_inv(&padded).unwrap(), original);
}

#[test]
fn pksc7_inv_rejects_zero_last_byte() {
    let bad = [0u8; 16];
    assert!(matches!(pksc7_inv(&bad), Err(PaddingError::SizeOutOfRange)));
}

#[test]
fn pksc7_inv_rejects_size_larger_than_block() {
    let mut bad = [0x11u8; 16];
    bad[15] = 17;
    assert!(matches!(pksc7_inv(&bad), Err(PaddingError::SizeOutOfRange)));
}

#[test]
fn pksc7_inv_rejects_inconsistent_bytes() {
    let mut bad = [0xAAu8; 16];
    bad[15] = 4;
    bad[14] = 4;
    bad[13] = 4;
    bad[12] = 0xCC; // should also be 4
    assert!(matches!(
        pksc7_inv(&bad),
        Err(PaddingError::InconsistentBytes)
    ));
}

#[test]
fn pksc7_inv_rejects_empty_input() {
    assert!(matches!(pksc7_inv(&[]), Err(PaddingError::Empty)));
}

// === Detecção de tampering em CBC ===

#[test]
fn cbc_decrypt_rejects_tampered_last_block() {
    let cipher = Aes128::new(&KEY);
    let plain = b"Hola mundo!!!!!!";
    let mut ct = cbc_encrypt(&cipher, &IV, plain);
    let last = ct.len() - 1;
    ct[last] ^= 0xff;

    // Probabilidade de pseudo-aleatório validar como padding válido é ~16/256;
    // se o teste falhar por isso, é flaky — mas para este vetor específico
    // sabemos que dá erro.
    assert!(cbc_decrypt(&cipher, &IV, &ct).is_err());
}

// O Byte alias é só para verificar que o módulo exporta tudo que precisamos.
#[allow(dead_code)]
fn _exports_check() -> Byte {
    0
}

//! Testes de integração para AES-GCM contra vetores NIST SP 800-38D.

use aes_rs::{gcm_decrypt, gcm_encrypt, Aes128, GcmAuthError};

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn key(s: &str) -> [u8; 16] {
    hex(s).try_into().unwrap()
}

fn block(s: &str) -> [u8; 16] {
    hex(s).try_into().unwrap()
}

#[test]
fn gcm_test_case_1_empty() {
    let cipher = Aes128::new(&key("00000000000000000000000000000000"));
    let iv = hex("000000000000000000000000");
    let expected_tag = block("58e2fccefa7e3061367f1d57a4e7455a");

    let ct = gcm_encrypt(&cipher, &iv, &[], &[]);
    assert!(ct.ciphertext.is_empty());
    assert_eq!(ct.tag, expected_tag);
}

#[test]
fn gcm_test_case_2_single_block() {
    let cipher = Aes128::new(&key("00000000000000000000000000000000"));
    let iv = hex("000000000000000000000000");
    let plain = hex("00000000000000000000000000000000");
    let expected_ct = hex("0388dace60b6a392f328c2b971b2fe78");
    let expected_tag = block("ab6e47d42cec13bdf53a67b21257bddf");

    let ct = gcm_encrypt(&cipher, &iv, &plain, &[]);
    assert_eq!(ct.ciphertext, expected_ct);
    assert_eq!(ct.tag, expected_tag);
}

#[test]
fn gcm_test_case_3_four_blocks() {
    let cipher = Aes128::new(&key("feffe9928665731c6d6a8f9467308308"));
    let iv = hex("cafebabefacedbaddecaf888");
    let plain = hex("d9313225f88406e5a55909c5aff5269a \
         86a7a9531534f7da2e4c303d8a318a72 \
         1c3c0c95956809532fcf0e2449a6b525 \
         b16aedf5aa0de657ba637b391aafd255");
    let expected_ct = hex("42831ec2217774244b7221b784d0d49c \
         e3aa212f2c02a4e035c17e2329aca12e \
         21d514b25466931c7d8f6a5aac84aa05 \
         1ba30b396a0aac973d58e091473f5985");
    let expected_tag = block("4d5c2af327cd64a62cf35abd2ba6fab4");

    let ct = gcm_encrypt(&cipher, &iv, &plain, &[]);
    assert_eq!(ct.ciphertext, expected_ct);
    assert_eq!(ct.tag, expected_tag);
}

#[test]
fn gcm_test_case_4_with_aad_and_partial_block() {
    let cipher = Aes128::new(&key("feffe9928665731c6d6a8f9467308308"));
    let iv = hex("cafebabefacedbaddecaf888");
    let plain = hex("d9313225f88406e5a55909c5aff5269a \
         86a7a9531534f7da2e4c303d8a318a72 \
         1c3c0c95956809532fcf0e2449a6b525 \
         b16aedf5aa0de657ba637b39");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let expected_ct = hex("42831ec2217774244b7221b784d0d49c \
         e3aa212f2c02a4e035c17e2329aca12e \
         21d514b25466931c7d8f6a5aac84aa05 \
         1ba30b396a0aac973d58e091");
    let expected_tag = block("5bc94fbc3221a5db94fae95ae7121a47");

    let ct = gcm_encrypt(&cipher, &iv, &plain, &aad);
    assert_eq!(ct.ciphertext, expected_ct);
    assert_eq!(ct.tag, expected_tag);
}

#[test]
fn gcm_round_trip() {
    let cipher = Aes128::new(&key("0f1571c947d9e8590cb7add6af7f6798"));
    let iv = hex("53616c7465645f5f7aadee8b");
    let plain = b"mensagem de comprimento qualquer";

    let ct = gcm_encrypt(&cipher, &iv, plain, &[]);
    let recovered = gcm_decrypt(&cipher, &iv, &ct.ciphertext, &ct.tag, &[]).unwrap();
    assert_eq!(recovered, plain);
}

#[test]
fn gcm_round_trip_with_aad() {
    let cipher = Aes128::new(&key("0f1571c947d9e8590cb7add6af7f6798"));
    let iv = hex("53616c7465645f5f7aadee8b");
    let plain = b"payload";
    let aad = b"cabecalho";

    let ct = gcm_encrypt(&cipher, &iv, plain, aad);
    let recovered = gcm_decrypt(&cipher, &iv, &ct.ciphertext, &ct.tag, aad).unwrap();
    assert_eq!(recovered, plain);
}

#[test]
fn gcm_decrypt_rejects_tampered_ciphertext() {
    let cipher = Aes128::new(&key("0f1571c947d9e8590cb7add6af7f6798"));
    let iv = hex("53616c7465645f5f7aadee8b");
    let plain = b"texto plano qualquer";

    let mut ct = gcm_encrypt(&cipher, &iv, plain, &[]);
    ct.ciphertext[0] ^= 0x01;
    assert_eq!(
        gcm_decrypt(&cipher, &iv, &ct.ciphertext, &ct.tag, &[]),
        Err(GcmAuthError)
    );
}

#[test]
fn gcm_decrypt_rejects_tampered_tag() {
    let cipher = Aes128::new(&key("0f1571c947d9e8590cb7add6af7f6798"));
    let iv = hex("53616c7465645f5f7aadee8b");
    let plain = b"texto plano qualquer";

    let ct = gcm_encrypt(&cipher, &iv, plain, &[]);
    let mut bad_tag = ct.tag;
    bad_tag[0] ^= 0x01;
    assert_eq!(
        gcm_decrypt(&cipher, &iv, &ct.ciphertext, &bad_tag, &[]),
        Err(GcmAuthError)
    );
}

#[test]
fn gcm_decrypt_rejects_wrong_aad() {
    let cipher = Aes128::new(&key("0f1571c947d9e8590cb7add6af7f6798"));
    let iv = hex("53616c7465645f5f7aadee8b");
    let plain = b"texto plano qualquer";

    let ct = gcm_encrypt(&cipher, &iv, plain, b"header");
    assert_eq!(
        gcm_decrypt(&cipher, &iv, &ct.ciphertext, &ct.tag, b"Header"),
        Err(GcmAuthError)
    );
}

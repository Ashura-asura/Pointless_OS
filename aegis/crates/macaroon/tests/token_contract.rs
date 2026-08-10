use capability_core::{ObjectKind, Rights};
use macaroon::{self, Caveat, TokenError};

fn test_key() -> [u8; 32] {
    [0xAB; 32]
}

fn test_kernel_id() -> [u8; 32] {
    object_store::sha256::sha256(b"test-kernel")
}

#[test]
fn mint_and_verify_roundtrip() {
    let key = test_key();
    let kid = test_kernel_id();
    let chain = macaroon::mint(&key, kid, 42, ObjectKind::Task, Rights::ALL, None);
    macaroon::verify(&key, &chain).expect("fresh token must verify");
    let bytes = macaroon::serialize_chain(&chain);
    let restored = macaroon::deserialize_chain(&bytes).expect("deserialize must succeed");
    assert_eq!(chain, restored);
    macaroon::verify(&key, &restored).expect("roundtripped token must verify");
}

#[test]
fn bind_caveat_narrows_rights() {
    let key = test_key();
    let kid = test_kernel_id();
    let chain = macaroon::mint(&key, kid, 7, ObjectKind::MemRegion, Rights::ALL, None);
    let narrowed = macaroon::bind_caveat(&key, &chain, Caveat::RightsNarrow(Rights::READ.bits()));
    macaroon::verify(&key, &narrowed).expect("narrowed token must verify");
    assert_eq!(narrowed.token.rights, Rights::READ.bits());
    assert_eq!(narrowed.token.caveats.len(), 1);
    assert!(narrowed
        .token
        .caveats
        .contains(&Caveat::RightsNarrow(Rights::READ.bits())));
}

#[test]
fn tampered_token_fails_verification() {
    let key = test_key();
    let kid = test_kernel_id();
    let chain = macaroon::mint(&key, kid, 99, ObjectKind::Endpoint, Rights::SEND, None);
    let mut bytes = macaroon::serialize_chain(&chain);
    bytes[4] ^= 0xFF;
    let tampered =
        macaroon::deserialize_chain(&bytes).expect("deserialize still works on bit-flip");
    let err = macaroon::verify(&key, &tampered).unwrap_err();
    assert_eq!(err, TokenError::ChainIntegrityError);
}

#[test]
fn custom_caveat_preserved_through_roundtrip() {
    let key = test_key();
    let kid = test_kernel_id();
    let chain = macaroon::mint(&key, kid, 1, ObjectKind::Task, Rights::ALL, None);
    let with_custom = macaroon::bind_caveat(&key, &chain, Caveat::Custom(b"ip:10.0.0.1".to_vec()));
    macaroon::verify(&key, &with_custom).expect("custom caveat token must verify");
    let bytes = macaroon::serialize_chain(&with_custom);
    let restored = macaroon::deserialize_chain(&bytes).expect("roundtrip");
    macaroon::verify(&key, &restored).expect("roundtripped custom caveat must verify");
    assert_eq!(
        restored.token.caveats,
        vec![Caveat::Custom(b"ip:10.0.0.1".to_vec())]
    );
}

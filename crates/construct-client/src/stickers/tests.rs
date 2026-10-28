use super::*;

/// The conformance vectors beside the protos: what every client reads from these bytes.
fn vectors(name: &str) -> serde_json::Value {
    let path = format!("{}/conformance/{name}", env!("CONSTRUCT_PROTOS_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json")
}

fn keys() -> Vec<Vec<u8>> {
    crate::trust::pinned_certificate_keys()
}

fn library(name: &str) -> Library {
    let dir =
        std::env::temp_dir().join(format!("konstruct-stickers-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Library::new(dir)
}

/// `knst_sticker_ref.json`: the bytes decode to the same reference, and the validator answers
/// every case the way every other client does.
#[test]
fn references_read_and_validate_as_the_vectors_say() {
    let v = vectors("knst_sticker_ref.json");
    for vector in v["vectors"].as_array().unwrap() {
        let payload = hex::decode(vector["message_content_hex"].as_str().unwrap()).unwrap();
        let r = crate::content::sticker(&payload).expect("the vector is a valid sticker");
        assert_eq!(r.pack_id, vector["pack_id_hex"].as_str().unwrap());
        assert_eq!(u64::from(r.index), vector["index"].as_u64().unwrap());
        assert_eq!(r.emoji, vector["emoji"].as_str().unwrap());
        // What this client sends is the same bytes.
        assert_eq!(crate::content::encode_sticker(&r).unwrap(), payload);
    }
    for case in v["cases"].as_array().unwrap() {
        let wire = wire::StickerRef {
            pack_id: hex::decode(case["pack_id_hex"].as_str().unwrap())
                .unwrap()
                .into(),
            index: 0,
            emoji: case["emoji"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            StickerRef::from_wire(&wire).is_some(),
            case["valid"].as_bool().unwrap(),
            "{case}"
        );
    }
}

/// `knst_sticker_pack.json`: a pack's id is the hash of the same canonical bytes here as on
/// iOS and at the publisher.
#[test]
fn a_pack_id_is_the_hash_of_the_canonical_manifest() {
    let v = vectors("knst_sticker_pack.json");
    let manifest_bytes = hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap();
    let manifest = wire::StickerPackManifest::decode(manifest_bytes.as_slice()).unwrap();
    assert_eq!(
        hex::encode(canonical(&manifest)),
        v["canonical_hex"].as_str().unwrap()
    );
    // The fixture is unsigned: right in every other way, and refused for that alone.
    assert_eq!(
        verify(&manifest_bytes, Signature::Check(&keys())),
        Err(VerifyError::Unsigned)
    );
    let pack = verify(&manifest_bytes, Signature::CheckedBefore).unwrap();
    assert_eq!(pack.hex_id(), v["pack_id_hex"].as_str().unwrap());
}

/// The app's own packs carry the server's signature and every sticker they name.
#[test]
fn the_bundled_packs_are_signed_and_whole() {
    for (manifest, _) in bundled::PACKS {
        let pack = verify(manifest, Signature::Check(&keys())).expect("signed by the pinned key");
        for entry in &pack.stickers {
            let hex = hex::encode(entry.sha256);
            let (_, bytes) = bundled::BLOBS
                .iter()
                .find(|(h, _)| *h == hex)
                .expect("every sticker is bundled");
            check_blob(entry, bytes).expect("a sticker is what its pack says");
        }
    }
}

/// A manifest changed in any way is not the pack: its hash moves, or its signature no longer
/// covers it.
#[test]
fn a_changed_manifest_is_refused() {
    let (manifest_bytes, _) = bundled::PACKS[1];
    let manifest = wire::StickerPackManifest::decode(manifest_bytes).unwrap();

    let mut retitled = manifest.clone();
    retitled.title = "Momo the dog".into();
    assert_eq!(
        verify(&retitled.encode_to_vec(), Signature::Check(&keys())),
        Err(VerifyError::PackIdMismatch)
    );

    // Re-hashed to match, so only the signature can tell.
    retitled.pack_id = Sha256::digest(canonical(&retitled)).to_vec().into();
    assert_eq!(
        verify(&retitled.encode_to_vec(), Signature::Check(&keys())),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify(manifest_bytes, Signature::Check(&[vec![9; 32]])),
        Err(VerifyError::BadSignature),
        "a key that is not the server's"
    );

    let mut oversized = manifest.clone();
    oversized.stickers[3].byte_len = MAX_STICKER_BYTES as u32 + 1;
    oversized.pack_id = Sha256::digest(canonical(&oversized)).to_vec().into();
    assert_eq!(
        verify(&oversized.encode_to_vec(), Signature::CheckedBefore),
        Err(VerifyError::BadEntry(3))
    );
}

/// Only a still 512×512 WebP is a sticker picture.
#[test]
fn only_a_still_sticker_sized_webp_is_a_picture() {
    let (_, real) = bundled::BLOBS[0];
    assert!(is_sticker_webp(real));
    // An extended header: still, then flagged as animated.
    let mut vp8x = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0".to_vec();
    vp8x.extend([0x10, 0, 0, 0, 0xFF, 0x01, 0, 0xFF, 0x01, 0]);
    assert!(is_sticker_webp(&vp8x));
    vp8x[20] |= 0x02;
    assert!(!is_sticker_webp(&vp8x), "animated");
    let mut small = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0".to_vec();
    small.extend([0, 0, 0, 0, 0xFF, 0, 0, 0xFF, 0, 0]);
    assert!(!is_sticker_webp(&small), "256×256");
    assert!(!is_sticker_webp(
        b"\x89PNG\r\n\x1a\n not a webp at all, though long enough"
    ));
}

/// Seeding puts the app's packs in place once: the current one offered, the retired one only
/// present, and a pack the person removed is not brought back.
#[test]
fn bundled_packs_are_seeded_once() {
    let lib = library("seed");
    assert_eq!(lib.seed_bundled(&keys()), 2);
    let retired = verify(bundled::PACKS[0].0, Signature::CheckedBefore).unwrap();
    let current = verify(bundled::PACKS[1].0, Signature::CheckedBefore).unwrap();
    assert_eq!(lib.listed(), vec![current.clone()]);
    // The retired pack still shows the stickers people sent with it.
    let old = retired.reference(0).unwrap();
    assert!(lib.image(&old).is_some());

    lib.set_listed(&current.hex_id(), false);
    assert_eq!(lib.seed_bundled(&keys()), 0);
    assert!(lib.listed().is_empty());
}

/// A sticker on disk that is not the file its pack names is not shown; a reference past the
/// end of its pack has no picture.
#[test]
fn a_picture_is_read_back_only_as_what_it_claims() {
    let lib = library("tamper");
    lib.seed_bundled(&keys());
    let pack = lib.listed().remove(0);
    let r = pack.reference(2).unwrap();
    assert!(lib.image(&r).is_some());
    std::fs::write(lib.blob_path(&pack.stickers[2].sha256), bundled::BLOBS[0].1).unwrap();
    assert_eq!(lib.image(&r), None);
    let beyond = StickerRef {
        index: pack.stickers.len() as u32,
        ..pack.reference(0).unwrap()
    };
    assert_eq!(lib.image(&beyond), None);
}

/// Recent stickers: newest first, one entry each, only from packs still offered.
#[test]
fn recent_stickers_are_newest_first_and_sendable() {
    let lib = library("recent");
    lib.seed_bundled(&keys());
    let pack = lib.listed().remove(0);
    let (a, b) = (pack.reference(0).unwrap(), pack.reference(1).unwrap());
    lib.record_used(&a);
    lib.record_used(&b);
    lib.record_used(&a);
    assert_eq!(lib.recent(), vec![a.clone(), b]);
    lib.set_listed(&pack.hex_id(), false);
    assert!(lib.recent().is_empty());
}

/// A pack id is a file name here, so only its one exact form is taken.
#[test]
fn a_pack_id_is_taken_only_as_64_lower_case_hex_digits() {
    let id = "ab".repeat(32);
    assert_eq!(pack_id(&id), Some([0xab; 32]));
    assert_eq!(pack_id(&id.to_uppercase()), None);
    assert_eq!(pack_id(&id[..62]), None);
    assert_eq!(pack_id(&format!("../{}", &id[3..])), None);
}

/// Against the server this build talks to: its catalog reads, and the app's pack comes back
/// whole and verified. `cargo test -- --ignored the_server_serves`.
#[ignore = "talks to the server"]
#[tokio::test]
async fn the_server_serves_packs() {
    let server = crate::config::load_config().unwrap_or_default().server;
    let anonymous = GrpcClient::new(&server);
    let packs = catalog(&anonymous).await.expect("catalog");
    eprintln!("catalog: {packs:?}");
    let lib = library("server");
    let id = verify(bundled::PACKS[1].0, Signature::CheckedBefore)
        .unwrap()
        .id;
    let pack = fetch(&anonymous, &lib, id, &keys()).await.expect("fetched");
    assert!(lib.image(&pack.reference(0).unwrap()).is_some());
}

use trace_commons_protocol::token_distribution::*;

fn token(bytes: &[u8]) -> TokenValue {
    TokenValue {
        bytes: bytes.to_vec(),
        token_id: None,
        logprob: LogProbability::Finite(-1.25),
    }
}
fn source(parts: &[&[u8]]) -> TokenDistribution {
    let mut offset = 0;
    TokenDistribution {
        version: SCHEMA_VERSION,
        capture_store_id: "store-1".into(),
        exchange_id: "exchange-1".into(),
        event_id: "event-1".into(),
        choice: 0,
        segment: 0,
        requested_model: "model".into(),
        served_model: None,
        tokenizer: None,
        semantics: ProbabilitySemantics::Unknown,
        conditioning: Conditioning::Original,
        requested_alternatives: 20,
        response_digest: ContentDigest::of(&parts.concat()),
        records: parts
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let start = offset;
                offset += bytes.len() as u64;
                TokenRecord {
                    index: i as u64,
                    span: ByteSpan { start, end: offset },
                    chosen: token(bytes),
                    alternatives: vec![token(b"alternative")],
                    returned_alternatives: 1,
                }
            })
            .collect(),
    }
}
fn manifest() -> ContributionBundleManifest {
    ContributionBundleManifest {
        version: 1,
        usage_profile: TokenUsageProfile::RestrictedResearch,
        submission_id: "s1".into(),
        bundle_revision: "r1".into(),
        envelope_digest: ContentDigest::of(b"envelope"),
        consent_digest: ContentDigest::of(b"consent"),
        policy_version: "p1".into(),
        attachments: vec![AttachmentDescriptor {
            artifact_id: "a1".into(),
            event_id: "event-1".into(),
            content_digest: ContentDigest::of(b"attachment"),
            size_bytes: 10,
        }],
    }
}
#[test]
fn split_utf8_bytes_are_aligned_without_lossy_conversion() {
    let value = source(&[&[0xc3], &[0xa9]]);
    assert!(value.validate("é".as_bytes()).is_ok());
    let encoded = serde_json::to_vec(&value).unwrap();
    assert!(TokenDistribution::decode(&encoded, "é".as_bytes()).is_ok());
    assert_eq!(value.validate(b"e"), Err(DistributionError::Digest));
}
#[test]
fn partial_duplicate_and_reordered_records_are_refused() {
    let mut value = source(&[b"a", b"b"]);
    value.records.swap(0, 1);
    assert_eq!(value.validate(b"ab"), Err(DistributionError::Alignment));
    value.records.swap(0, 1);
    value.records.pop();
    assert_eq!(value.validate(b"ab"), Err(DistributionError::Alignment));
}
#[test]
fn impossible_numbers_and_excessive_alternatives_are_refused() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.01] {
        let mut value = source(&[b"a"]);
        value.records[0].chosen.logprob = LogProbability::Finite(bad);
        assert_eq!(value.validate(b"a"), Err(DistributionError::Invalid));
    }
    let mut value = source(&[b"a"]);
    value.records[0].alternatives = vec![token(b"x"); 21];
    value.records[0].returned_alternatives = 21;
    assert_eq!(value.validate(b"a"), Err(DistributionError::Limit));
}
#[test]
fn future_schemas_and_unknown_fields_fail_closed() {
    let mut value = serde_json::to_value(source(&[b"a"])).unwrap();
    value["version"] = 2.into();
    assert!(matches!(
        TokenDistribution::decode(&serde_json::to_vec(&value).unwrap(), b"a"),
        Err(DistributionError::Version)
    ));
    value["version"] = 1.into();
    value["future_raw_field"] = "secret".into();
    assert!(TokenDistribution::decode(&serde_json::to_vec(&value).unwrap(), b"a").is_err());
}
#[test]
fn overlapping_tokens_and_their_alternatives_disappear_and_offsets_shift() {
    let source = source(&[b"Hi ", b"Ali", b"ce", b"!"]);
    let edits = [RedactionEdit {
        original: ByteSpan { start: 3, end: 8 },
        replacement: b"[NAME]".to_vec(),
    }];
    let output = filter_with_edits(
        &source,
        b"Hi Alice!",
        b"Hi [NAME]!",
        &edits,
        "p1",
        |_, _, _| Some(vec![true]),
    )
    .unwrap();
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.omitted_records, 2);
    assert_eq!(output.records[1].span, ByteSpan { start: 9, end: 10 });
    assert_eq!(output.records[1].index, 1);
    assert!(
        !String::from_utf8(serde_json::to_vec(&output).unwrap())
            .unwrap()
            .contains("original_offset")
    );
}
#[test]
fn partial_token_overlap_drops_the_whole_record() {
    let source = source(&[b"HelloAlice", b"!"]);
    let output = filter_with_edits(
        &source,
        b"HelloAlice!",
        b"Hello[X]!",
        &[RedactionEdit {
            original: ByteSpan { start: 5, end: 10 },
            replacement: b"[X]".to_vec(),
        }],
        "p1",
        |_, _, _| Some(vec![true]),
    )
    .unwrap();
    assert_eq!(output.records.len(), 1);
    assert_eq!(output.records[0].chosen.bytes, b"!");
}
#[test]
fn uncertain_alternative_screening_drops_the_position() {
    let source = source(&[b"hello"]);
    for decision in [None, Some(vec![])] {
        let output = filter_with_edits(&source, b"hello", b"hello", &[], "p1", |_, _, _| {
            decision.clone()
        })
        .unwrap();
        assert!(output.records.is_empty());
        assert_eq!(output.omitted_records, 1);
    }
}
#[test]
fn alternatives_can_be_removed_without_renormalizing() {
    let mut source = source(&[b"hello"]);
    source.records[0].alternatives.push(token(b"safe"));
    source.records[0].returned_alternatives = 2;
    let output = filter_with_edits(&source, b"hello", b"hello", &[], "p1", |_, _, _| {
        Some(vec![false, true])
    })
    .unwrap();
    assert_eq!(output.omitted_alternatives, 1);
    assert!(matches!(
        output.records[0].alternatives[0].logprob,
        LogProbability::Finite(-1.25)
    ));
    assert!(matches!(
        output.records[0].chosen.logprob,
        LogProbability::Finite(-1.25)
    ));
}
#[test]
fn mismatched_or_overlapping_edit_maps_are_refused() {
    let source = source(&[b"abc"]);
    let edit = RedactionEdit {
        original: ByteSpan { start: 0, end: 2 },
        replacement: b"X".to_vec(),
    };
    assert!(matches!(
        filter_with_edits(
            &source,
            b"abc",
            b"Yc",
            std::slice::from_ref(&edit),
            "p1",
            |_, _, _| Some(vec![true])
        ),
        Err(DistributionError::Redaction)
    ));
    assert!(matches!(
        filter_with_edits(
            &source,
            b"abc",
            b"Xc",
            &[edit.clone(), edit],
            "p1",
            |_, _, _| Some(vec![true])
        ),
        Err(DistributionError::Redaction)
    ));
}
#[test]
fn repeated_text_does_not_get_greedily_realigned() {
    let source = source(&[b"Ann", b" ", b"Ann"]);
    let output = filter_with_edits(
        &source,
        b"Ann Ann",
        b"[X] Ann",
        &[RedactionEdit {
            original: ByteSpan { start: 0, end: 3 },
            replacement: b"[X]".to_vec(),
        }],
        "p1",
        |_, _, _| Some(vec![true]),
    )
    .unwrap();
    assert_eq!(output.records.len(), 2);
    assert_eq!(output.records[1].span, ByteSpan { start: 4, end: 7 });
}
#[test]
fn manifest_binds_attachment_bytes_order_revision_and_consent() {
    let value = manifest();
    assert!(value.verify_attachment("a1", b"attachment").is_ok());
    assert_eq!(
        value.verify_attachment("a1", b"attachmenT"),
        Err(DistributionError::Digest)
    );
    let mut other = value.clone();
    other.bundle_revision = "r2".into();
    assert_ne!(value.digest().unwrap(), other.digest().unwrap());
    other = value.clone();
    other.consent_digest = ContentDigest::of(b"different consent");
    assert_ne!(value.digest().unwrap(), other.digest().unwrap());
    other = value.clone();
    other.attachments.push(other.attachments[0].clone());
    assert_eq!(other.validate(), Err(DistributionError::Invalid));
}
#[test]
fn receipt_for_another_account_revision_or_expired_retention_cannot_match() {
    let manifest = manifest();
    let receipt = DurableBundleReceipt {
        version: 1,
        server_id: "server".into(),
        tenant_id: "tenant".into(),
        account_id: "account".into(),
        submission_id: "s1".into(),
        bundle_revision: "r1".into(),
        manifest_digest: manifest.digest().unwrap(),
        committed_at_unix: 10,
        retain_until_unix: 100,
        retention_policy_version: "retention-v1".into(),
    };
    assert!(
        receipt
            .matches_bundle(&manifest, "server", "tenant", "account", 20)
            .is_ok()
    );
    for (server, tenant, account, now) in [
        ("evil", "tenant", "account", 20),
        ("server", "other", "account", 20),
        ("server", "tenant", "other", 20),
        ("server", "tenant", "account", 100),
        ("server", "tenant", "account", 9),
    ] {
        assert_eq!(
            receipt.matches_bundle(&manifest, server, tenant, account, now),
            Err(DistributionError::Receipt)
        );
    }
    let mut revised = manifest.clone();
    revised.bundle_revision = "r2".into();
    assert_eq!(
        receipt.matches_bundle(&revised, "server", "tenant", "account", 20),
        Err(DistributionError::Receipt)
    );
}

#[test]
fn fp64_round_trips_without_quantization_or_non_finite_json_nulls() {
    for n in [
        -0.0,
        -1.2345678901234567,
        -f64::MIN_POSITIVE,
        -f64::MAX,
        -f64::from_bits(1),
    ] {
        let value = LogProbability::Finite(n);
        let wire = serde_json::to_vec(&value).unwrap();
        let LogProbability::Finite(decoded) = serde_json::from_slice(&wire).unwrap() else {
            panic!("lost value")
        };
        assert_eq!(decoded.to_bits(), n.to_bits());
    }
    assert!(serde_json::to_vec(&LogProbability::Finite(f64::NAN)).is_err());
    assert!(serde_json::from_str::<LogProbability>(r#"{"kind":"finite","value":"NaN"}"#).is_err());
}

#[test]
fn rescrubbed_text_invalidates_previously_valid_attachments() {
    let output = filter_with_edits(
        &source(&[b"hello"]),
        b"hello",
        b"hello",
        &[],
        "p1",
        |_, _, _| Some(vec![true]),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&output).unwrap();
    let mut manifest = manifest();
    manifest.attachments[0].size_bytes = bytes.len() as u64;
    manifest.attachments[0].content_digest = ContentDigest::of(&bytes);
    assert!(
        manifest
            .verify_sanitized_attachment("a1", &bytes, b"hello")
            .is_ok()
    );
    assert!(matches!(
        manifest.verify_sanitized_attachment("a1", &bytes, b"[REDACTED]"),
        Err(DistributionError::Digest)
    ));
    manifest.attachments[0].event_id = "different-event".into();
    assert!(matches!(
        manifest.verify_sanitized_attachment("a1", &bytes, b"hello"),
        Err(DistributionError::Digest)
    ));
}
#[test]
fn canonical_manifest_decode_rejects_duplicate_keys_and_alternate_encodings() {
    let manifest = manifest();
    let bytes = manifest.canonical_bytes().unwrap();
    assert!(ContributionBundleManifest::decode(&bytes).is_ok());
    let spaced = format!(" {}", String::from_utf8(bytes).unwrap());
    assert!(ContributionBundleManifest::decode(spaced.as_bytes()).is_err());
    let duplicate = spaced.replace("\"version\":1", "\"version\":1,\"version\":1");
    assert!(ContributionBundleManifest::decode(duplicate.as_bytes()).is_err());
}

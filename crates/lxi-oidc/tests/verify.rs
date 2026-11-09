//! The verifier's rules, ported from JSR `crates/api-rest/tests/rest.rs` (3b75827) with
//! the same assertions; `Verified` replaces JSR's `Principal`.
#![forbid(unsafe_code, unused_must_use)]
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::dbg_macro
)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lxi_oidc::{Kind, Settings, TokenError, Verifier};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(format!("{FIXTURES}/{name}"))?)
}

fn settings() -> Settings {
    Settings {
        issuer: "https://issuer.example".into(),
        audience: "api://jsr".into(),
        jwks_file: PathBuf::from(format!("{FIXTURES}/jwks.json")),
        algorithms: vec!["RS256".into()],
        groups_claim: "groups".into(),
        subject_claim: "sub".into(),
        application_claim: "idtyp".into(),
        application_value: "app".into(),
    }
}

fn now() -> TestResult<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

fn at(offset: i64) -> TestResult<i64> {
    now()?.checked_add(offset).ok_or_else(|| "time".into())
}

fn claims() -> TestResult<Value> {
    Ok(json!({
        "iss": "https://issuer.example",
        "aud": "api://jsr",
        "sub": "ana@example.com",
        "exp": at(600)?,
        "nbf": at(-10)?,
        "groups": ["jsroper", "sales"],
    }))
}

fn set(claims: &mut Value, field: &str, value: Value) -> TestResult {
    claims
        .as_object_mut()
        .ok_or("claims")?
        .insert(field.into(), value);
    Ok(())
}

fn remove(claims: &mut Value, field: &str) -> TestResult {
    claims.as_object_mut().ok_or("claims")?.remove(field);
    Ok(())
}

fn token_with(claims: &Value, key: &str, kid: Option<&str>) -> TestResult<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    Ok(encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(fixture(key)?.as_bytes())?,
    )?)
}

fn token(claims: &Value) -> TestResult<String> {
    token_with(claims, "trusted.pem", Some("test-key-1"))
}

fn verifier() -> TestResult<Verifier> {
    Ok(Verifier::new(&settings(), &fixture("jwks.json")?)?)
}

fn base64_url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut count: u32 = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        count = count.saturating_add(8);
        while count >= 6 {
            count = count.saturating_sub(6);
            let index = usize::try_from((bits >> count) & 63).unwrap_or(0);
            out.push(char::from(*TABLE.get(index).unwrap_or(&b'A')));
        }
    }
    if count > 0 {
        let index = usize::try_from((bits << 6u32.saturating_sub(count)) & 63).unwrap_or(0);
        out.push(char::from(*TABLE.get(index).unwrap_or(&b'A')));
    }
    out
}

#[test]
fn a_valid_token_gives_a_user_principal_with_groups() -> TestResult {
    let verified = verifier()?.verify(&token(&claims()?)?)?;
    assert_eq!(verified.kind, Kind::User);
    assert_eq!(verified.name, "ana@example.com");
    assert_eq!(verified.sub, "ana@example.com");
    assert!(verified.groups.contains("sales"));
    Ok(())
}

#[test]
fn an_application_token_is_a_technical_client() -> TestResult {
    let mut c = claims()?;
    set(&mut c, "idtyp", json!("app"))?;
    assert_eq!(verifier()?.verify(&token(&c)?)?.kind, Kind::Application);
    Ok(())
}

#[test]
fn invalid_tokens_are_rejected() -> TestResult {
    let verifier = verifier()?;
    let reject = |t: &str| verifier.verify(t).err();

    assert_eq!(reject("not-a-jwt"), Some(TokenError::Malformed));
    // Signed with a key the issuer does not have.
    assert!(matches!(
        reject(&token_with(&claims()?, "foreign.pem", Some("test-key-1"))?),
        Some(TokenError::Invalid(_))
    ));
    assert_eq!(
        reject(&token_with(&claims()?, "trusted.pem", Some("other-kid"))?),
        Some(TokenError::UnknownKey)
    );
    for (field, value) in [
        ("aud", json!("api://other")),
        ("iss", json!("https://evil.example")),
        ("exp", json!(at(-3600)?)),
        ("nbf", json!(at(3600)?)),
        // Time claims of the wrong type: jsonwebtoken 9 skips a malformed nbf as if it
        // were absent (GHSA-h395-gr6q-cpjc), so the verifier checks their type itself.
        ("nbf", json!(at(3600)?.to_string())),
        ("exp", json!("never")),
        ("iat", json!("yesterday")),
    ] {
        let mut c = claims()?;
        set(&mut c, field, value)?;
        assert!(
            matches!(reject(&token(&c)?), Some(TokenError::Invalid(_))),
            "{field}"
        );
    }
    let mut c = claims()?;
    remove(&mut c, "sub")?;
    assert!(matches!(
        reject(&token(&c)?),
        Some(TokenError::Invalid(_) | TokenError::NoSubject)
    ));

    // alg=none and HS256 signed with the JWKS text (algorithm confusion).
    let none = format!(
        "{}.{}.",
        base64_url(br#"{"alg":"none","typ":"JWT"}"#),
        base64_url(claims()?.to_string().as_bytes())
    );
    assert!(verifier.verify(&none).is_err());
    let hs = encode(
        &Header::new(Algorithm::HS256),
        &claims()?,
        &EncodingKey::from_secret(fixture("jwks.json")?.as_bytes()),
    )?;
    assert!(verifier.verify(&hs).is_err());
    Ok(())
}

/// New in lxi-oidc: the public key itself as the HMAC secret, with the right kid.
#[test]
fn an_hs256_token_signed_with_the_public_key_is_rejected() -> TestResult {
    let jwks: Value = serde_json::from_str(&fixture("jwks.json")?)?;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-1".into());
    for secret in [jwks.to_string(), fixture("trusted.pem")?] {
        let hs = encode(
            &header,
            &claims()?,
            &EncodingKey::from_secret(secret.as_bytes()),
        )?;
        assert!(matches!(
            verifier()?.verify(&hs),
            Err(TokenError::Invalid(_))
        ));
    }
    Ok(())
}

/// New in lxi-oidc: the `typ: ID` rule of JSR's verifier (S-19) had no test there.
#[test]
fn an_id_token_is_not_an_access_token() -> TestResult {
    for typ in ["ID", "id"] {
        let mut c = claims()?;
        set(&mut c, "typ", json!(typ))?;
        assert!(matches!(
            verifier()?.verify(&token(&c)?),
            Err(TokenError::Invalid(_))
        ));
    }
    let mut c = claims()?;
    set(&mut c, "typ", json!("Bearer"))?;
    assert!(verifier()?.verify(&token(&c)?).is_ok());
    Ok(())
}

#[test]
fn hmac_algorithms_cannot_be_configured() -> TestResult {
    for alg in ["HS256", "HS384", "HS512", "none", ""] {
        let mut s = settings();
        s.algorithms = vec![alg.into()];
        assert!(Verifier::new(&s, &fixture("jwks.json")?).is_err(), "{alg}");
    }
    let mut s = settings();
    s.algorithms = Vec::new();
    assert!(Verifier::new(&s, &fixture("jwks.json")?).is_err());
    Ok(())
}

#[test]
fn the_subject_claim_names_the_principal() -> TestResult {
    let mut s = settings();
    s.subject_claim = "preferred_username".into();
    let verifier = Verifier::new(&s, &fixture("jwks.json")?)?;
    let mut c = claims()?;
    set(&mut c, "preferred_username", json!("ana"))?;
    let verified = verifier.verify(&token(&c)?)?;
    assert_eq!(verified.name, "ana");
    assert_eq!(verified.sub, "ana@example.com");

    // A user without it is refused: never named by sub instead.
    for missing in [json!(null), json!(""), json!(42)] {
        let mut c = claims()?;
        set(&mut c, "preferred_username", missing.clone())?;
        assert_eq!(
            verifier.verify(&token(&c)?).err(),
            Some(TokenError::NoSubjectClaim("preferred_username".into())),
            "{missing}"
        );
    }
    // A token still needs sub, whatever names the principal.
    let mut c = claims()?;
    set(&mut c, "preferred_username", json!("ana"))?;
    remove(&mut c, "sub")?;
    assert!(verifier.verify(&token(&c)?).is_err());

    // A technical client may lack it: then sub names it.
    let mut c = claims()?;
    set(&mut c, "idtyp", json!("app"))?;
    let verified = verifier.verify(&token(&c)?)?;
    assert_eq!(verified.kind, Kind::Application);
    assert_eq!(verified.name, "ana@example.com");
    set(
        &mut c,
        "preferred_username",
        json!("service-account-portal"),
    )?;
    assert_eq!(verifier.verify(&token(&c)?)?.name, "service-account-portal");
    Ok(())
}

/// A `jwks_file` of its own for one test, starting with the issuer's first key.
fn jwks_file(test: &str) -> TestResult<(Settings, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("lxi-jwks-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("jwks.json");
    std::fs::write(&path, fixture("jwks.json")?)?;
    let mut s = settings();
    s.jwks_file = path.clone();
    Ok((s, path))
}

fn rotated_token() -> TestResult<String> {
    token_with(&claims()?, "rotated.pem", Some("test-key-2"))
}

#[test]
fn a_reload_reads_rotated_keys_and_drops_retired_ones() -> TestResult {
    let (s, path) = jwks_file("reload")?;
    let verifier = Verifier::from_file(&s)?.with_read_interval(Duration::from_secs(3600));
    assert!(verifier.verify(&token(&claims()?)?).is_ok());

    std::fs::write(&path, fixture("jwks-rotated.json")?)?;
    assert_eq!(verifier.reload()?, 2);
    assert!(verifier.verify(&rotated_token()?).is_ok());
    assert!(verifier.verify(&token(&claims()?)?).is_ok());

    // The issuer retires its first key: tokens signed with it stop being accepted.
    let rotated: Value = serde_json::from_str(&fixture("jwks-rotated.json")?)?;
    let second = rotated
        .get("keys")
        .and_then(|k| k.get(1))
        .ok_or("second key")?;
    std::fs::write(&path, json!({ "keys": [second] }).to_string())?;
    assert_eq!(verifier.reload()?, 1);
    assert_eq!(
        verifier.verify(&token(&claims()?)?).err(),
        Some(TokenError::UnknownKey)
    );
    assert!(verifier.verify(&rotated_token()?).is_ok());
    Ok(())
}

#[test]
fn a_bad_jwks_file_on_reload_keeps_the_keys_in_use() -> TestResult {
    let (s, path) = jwks_file("bad")?;
    let verifier = Verifier::from_file(&s)?;
    for bad in ["not json", r#"{"keys": []}"#] {
        std::fs::write(&path, bad)?;
        assert!(verifier.reload().is_err(), "{bad}");
        assert!(verifier.verify(&token(&claims()?)?).is_ok(), "{bad}");
    }
    std::fs::remove_file(&path)?;
    assert!(verifier.reload().is_err());
    assert!(verifier.verify(&token(&claims()?)?).is_ok());
    Ok(())
}

#[test]
fn an_unknown_kid_reads_the_file_again_at_most_once_per_interval() -> TestResult {
    let (s, path) = jwks_file("kid")?;
    let verifier = Verifier::from_file(&s)?.with_read_interval(Duration::from_secs(3600));
    // Rotated at the issuer and fetched into the file, without a reload: the first token
    // with the new kid makes the verifier read the file.
    std::fs::write(&path, fixture("jwks-rotated.json")?)?;
    assert!(verifier.verify(&rotated_token()?).is_ok());

    // Within the interval, made-up kids do not read the file again.
    std::fs::write(&path, fixture("jwks.json")?)?;
    assert_eq!(
        verifier
            .verify(&token_with(&claims()?, "trusted.pem", Some("made-up"))?)
            .err(),
        Some(TokenError::UnknownKey)
    );
    assert!(verifier.verify(&rotated_token()?).is_ok());

    // Keys given as text have no file to read again.
    let fixed = Verifier::new(&settings(), &fixture("jwks.json")?)?;
    assert_eq!(
        fixed.verify(&rotated_token()?).err(),
        Some(TokenError::UnknownKey)
    );
    assert!(fixed.reload().is_err());
    Ok(())
}

#[test]
fn a_key_read_again_is_checked_like_any_other() -> TestResult {
    let (s, path) = jwks_file("checked")?;
    let verifier = Verifier::from_file(&s)?;
    std::fs::write(&path, fixture("jwks-rotated.json")?)?;
    // A new key does not make the issuer, audience or expiry optional.
    let mut c = claims()?;
    set(&mut c, "iss", json!("https://evil.example"))?;
    assert!(matches!(
        verifier.verify(&token_with(&c, "rotated.pem", Some("test-key-2"))?),
        Err(TokenError::Invalid(_))
    ));
    Ok(())
}

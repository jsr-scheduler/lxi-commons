//! OIDC access tokens, verified as JSR verifies them (`crates/api-rest/src/auth.rs`,
//! 3b75827; JSR ADR-0009).
//!
//! Signature, algorithm, issuer, audience, expiry and not-before are validated against the
//! settings; nothing about trust is derived from the token itself. Keys come from the
//! issuer's JWKS, kept by the operator in `jwks_file`, and read again on a reload and on an
//! unknown `kid`: keys rotate. What a verified token means (which profile, which role) is
//! the service's decision.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

/// Clock skew tolerated on `exp` and `nbf`, in seconds.
const LEEWAY_SECONDS: u64 = 60;

/// Least time between two reads of the JWKS caused by unknown `kid`s.
const UNKNOWN_KID_INTERVAL: Duration = Duration::from_secs(30);

/// What the service configures; JSR's `OidcConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub issuer: String,
    pub audience: String,
    /// Asymmetric algorithms only (`RS256`, `ES256`, …); HMAC is refused.
    pub algorithms: Vec<String>,
    pub jwks_file: PathBuf,
    /// The claim that names a user; `sub` is still required.
    pub subject_claim: String,
    pub groups_claim: String,
    /// A token whose `application_claim` equals `application_value` is an application.
    pub application_claim: String,
    pub application_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Jwks(String),
    Algorithm(String),
    NoKeys,
    Read(String, String),
    NoFile,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jwks(e) => write!(f, "invalid JWKS: {e}"),
            Self::Algorithm(a) => write!(f, "unsupported algorithm {a}"),
            Self::NoKeys => f.write_str("the JWKS has no usable key"),
            Self::Read(path, e) => write!(f, "cannot read {path}: {e}"),
            Self::NoFile => f.write_str("no jwks_file to read again"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Why a token was rejected. Details belong in the service log, not in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Missing,
    Malformed,
    UnknownKey,
    Invalid(String),
    NoSubject,
    NoSubjectClaim(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("missing bearer token"),
            Self::Malformed => f.write_str("malformed token"),
            Self::UnknownKey => f.write_str("no key for this token"),
            Self::Invalid(why) => write!(f, "invalid token: {why}"),
            Self::NoSubject => f.write_str("token without subject"),
            Self::NoSubjectClaim(claim) => {
                write!(f, "user token without the subject claim {claim}")
            }
        }
    }
}

impl std::error::Error for TokenError {}

/// A person or an application (JSR `PrincipalKind::User` / `Application`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    User,
    Application,
}

/// A verified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub kind: Kind,
    /// The `subject_claim`, or `sub` for an application without it.
    pub name: String,
    pub sub: String,
    pub groups: BTreeSet<String>,
    /// `exp` claim, seconds since the Unix epoch.
    pub expires: i64,
}

struct Key {
    kid: Option<String>,
    key: DecodingKey,
}

pub struct Verifier {
    keys: RwLock<Arc<Vec<Key>>>,
    /// Where the keys are read again from; none for keys given as text.
    file: Option<PathBuf>,
    /// When unknown `kid`s last caused a read, and the least time between two.
    last_read: Mutex<Option<Instant>>,
    read_interval: Duration,
    validation: Validation,
    groups_claim: String,
    subject_claim: String,
    application_claim: String,
    application_value: String,
    log: Option<fn(&str)>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("keys", &self.current().len())
            .field("issuer", &self.validation.iss)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    pub fn new(settings: &Settings, jwks: &str) -> Result<Self, ConfigError> {
        let algorithms = settings
            .algorithms
            .iter()
            .map(|a| {
                let alg = Algorithm::from_str(a).map_err(|_| ConfigError::Algorithm(a.clone()))?;
                // Asymmetric only: an HMAC algorithm would turn a public key into a secret.
                match alg {
                    Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                        Err(ConfigError::Algorithm(a.clone()))
                    }
                    other => Ok(other),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let first = *algorithms
            .first()
            .ok_or_else(|| ConfigError::Algorithm("none configured".into()))?;
        let keys = parse_keys(jwks)?;
        let mut validation = Validation::new(first);
        validation.algorithms = algorithms;
        validation.set_issuer(&[settings.issuer.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECONDS;
        Ok(Self {
            keys: RwLock::new(Arc::new(keys)),
            file: None,
            last_read: Mutex::new(None),
            read_interval: UNKNOWN_KID_INTERVAL,
            validation,
            groups_claim: settings.groups_claim.clone(),
            subject_claim: settings.subject_claim.clone(),
            application_claim: settings.application_claim.clone(),
            application_value: settings.application_value.clone(),
            log: None,
        })
    }

    /// Keys read from `settings.jwks_file`, which is read again by `reload` and when a
    /// token names an unknown `kid`.
    pub fn from_file(settings: &Settings) -> Result<Self, ConfigError> {
        let jwks = read(&settings.jwks_file)?;
        let mut verifier = Self::new(settings, &jwks)?;
        verifier.file = Some(settings.jwks_file.clone());
        Ok(verifier)
    }

    /// The least time between two reads caused by unknown `kid`s (30 s by default).
    #[must_use]
    pub fn with_read_interval(mut self, interval: Duration) -> Self {
        self.read_interval = interval;
        self
    }

    /// Where a read caused by an unknown `kid` is reported (JSR wrote it to stderr with
    /// its own prefix; the service chooses).
    #[must_use]
    pub fn with_log(mut self, log: fn(&str)) -> Self {
        self.log = Some(log);
        self
    }

    /// Reads `jwks_file` again and returns how many keys are now in use. On any error the
    /// keys in use stay as they were.
    pub fn reload(&self) -> Result<usize, ConfigError> {
        let path = self.file.as_ref().ok_or(ConfigError::NoFile)?;
        let keys = parse_keys(&read(path)?)?;
        let count = keys.len();
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
        Ok(count)
    }

    fn current(&self) -> Arc<Vec<Key>> {
        Arc::clone(&self.keys.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether an unknown `kid` may cause a read now; records it when it may.
    fn may_read(&self) -> bool {
        if self.file.is_none() {
            return false;
        }
        let mut last = self
            .last_read
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if last.is_some_and(|at| now.saturating_duration_since(at) < self.read_interval) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// Verifies a compact JWT.
    pub fn verify(&self, token: &str) -> Result<Verified, TokenError> {
        let header = decode_header(token).map_err(|_| TokenError::Malformed)?;
        let mut keys = self.current();
        if find(&keys, header.kid.as_deref()).is_none() && header.kid.is_some() && self.may_read() {
            let message = match self.reload() {
                Ok(count) => format!("oidc: unknown key id; jwks_file read again, {count} keys"),
                Err(e) => format!("oidc: unknown key id; jwks_file kept: {e}"),
            };
            if let Some(log) = self.log {
                log(&message);
            }
            keys = self.current();
        }
        let key = find(&keys, header.kid.as_deref()).ok_or(TokenError::UnknownKey)?;
        let data = decode::<Map<String, Value>>(token, &key.key, &self.validation)
            .map_err(|e| TokenError::Invalid(e.to_string()))?;
        let claims = data.claims;
        // jsonwebtoken 9 skips a time claim it cannot parse as a u64 as if it were absent
        // (GHSA-h395-gr6q-cpjc): a string, a fraction or a negative `nbf` would pass.
        // Present means whole seconds (JSR checked only for a number).
        for name in ["exp", "nbf", "iat"] {
            if claims.get(name).is_some_and(|v| v.as_u64().is_none()) {
                return Err(TokenError::Invalid(format!("{name} is not whole seconds")));
            }
        }
        let text = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        let sub = text("sub").ok_or(TokenError::NoSubject)?;
        // An ID token proves a sign-in to its client; it is not a grant for this API.
        if text("typ").is_some_and(|t| t.eq_ignore_ascii_case("ID")) {
            return Err(TokenError::Invalid(
                "an ID token is not an access token".into(),
            ));
        }
        let groups: BTreeSet<String> = match claims.get(&self.groups_claim) {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            Some(Value::String(one)) => BTreeSet::from([one.clone()]),
            _ => BTreeSet::new(),
        };
        let application = claims
            .get(&self.application_claim)
            .and_then(Value::as_str)
            .is_some_and(|v| v == self.application_value);
        // A user without the configured claim is refused, never named by `sub` instead;
        // a technical client may lack it.
        let name = match text(&self.subject_claim) {
            Some(name) => name,
            None if application => sub,
            None => return Err(TokenError::NoSubjectClaim(self.subject_claim.clone())),
        };
        let expires = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| TokenError::Invalid("exp".into()))?;
        Ok(Verified {
            kind: if application {
                Kind::Application
            } else {
                Kind::User
            },
            name: name.to_owned(),
            sub: sub.to_owned(),
            groups,
            expires,
        })
    }
}

fn find<'k>(keys: &'k [Key], kid: Option<&str>) -> Option<&'k Key> {
    match kid {
        Some(kid) => keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
        None if keys.len() == 1 => keys.first(),
        None => None,
    }
}

fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path)
        .map_err(|e| ConfigError::Read(path.display().to_string(), e.to_string()))
}

fn parse_keys(jwks: &str) -> Result<Vec<Key>, ConfigError> {
    let set: JwkSet = serde_json::from_str(jwks).map_err(|e| ConfigError::Jwks(e.to_string()))?;
    let keys: Vec<Key> = set
        .keys
        .iter()
        .filter_map(|jwk| {
            DecodingKey::from_jwk(jwk).ok().map(|key| Key {
                kid: jwk.common.key_id.clone(),
                key,
            })
        })
        .collect();
    if keys.is_empty() {
        return Err(ConfigError::NoKeys);
    }
    Ok(keys)
}

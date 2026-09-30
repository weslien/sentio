//! Trusted-issuer OIDC bearer verification with per-mailbox identity.
//!
//! Sentio accepts two bearer families:
//!
//! 1. Sentio API keys (opaque, sha256-looked-up in `api_keys`) — service and
//!    admin credentials, tenant-wide.
//! 2. JWTs from trusted platform issuers (Dex for users, evroc-passport EITs
//!    for agents). The JWT `sub` (+ `iss`) is mapped through the
//!    `mailbox_identities` table to exactly one mailbox; the tenant is
//!    derived from the mailbox's domain. A JWT-authenticated caller is
//!    scoped to their own mailbox: they can read and send mail addressed to
//!    or from their mailbox, and nothing else.
//!
//! Signatures are verified against the issuer's JWKS endpoint (ES256; RS256
//! supported for self-hosted Dex that uses RSA), cached in-process with a
//! short TTL. `exp`/`nbf` are enforced; `iss` must match a configured
//! trusted issuer exactly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::errors::ApiError;

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// A trusted OIDC issuer whose JWTs are accepted as bearer credentials.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedIssuer {
    /// Exact `iss` claim value that must appear in the token.
    pub issuer: String,
    /// JWKS endpoint, e.g. `https://dex.platform.weslien.org/keys`.
    pub jwks_url: String,
    /// If set, the token's `aud` claim must contain this value. Prevents
    /// tokens minted for other platform services from being replayed
    /// against Sentio (token substitution).
    pub audience: Option<String>,
}

/// Verifier for trusted-issuer JWTs, with a per-issuer JWKS cache.
pub struct JwtVerifier {
    issuers: Vec<TrustedIssuer>,
    // issuer -> (jwks, fetched_at)
    cache: RwLock<HashMap<String, (Jwks, Instant)>>,
    http: reqwest::Client,
}

/// How long a fetched JWKS is reused before re-fetch.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// Clock skew tolerance for exp/nbf.
const SKEW: i64 = 30;

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    /// Base64url-encoded EC point (uncompressed), x coordinate.
    #[serde(default)]
    pub x: Option<String>,
    /// Base64url-encoded EC point, y coordinate.
    #[serde(default)]
    pub y: Option<String>,
    /// Base64url-encoded RSA modulus.
    #[serde(default)]
    pub n: Option<String>,
    /// Base64url-encoded RSA exponent.
    #[serde(default)]
    pub e: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Audience(s). `aud` may be a string or an array of strings.
    #[serde(default, deserialize_with = "de_string_or_vec")]
    pub aud: Vec<String>,
}

fn de_string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Aud::deserialize(d)? {
        Aud::One(s) => vec![s],
        Aud::Many(v) => v,
    })
}

impl JwtVerifier {
    pub fn new(issuers: Vec<TrustedIssuer>) -> Self {
        Self {
            issuers,
            cache: RwLock::new(HashMap::new()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    /// Verify an untrusted bearer JWT. Returns the accepted claims on
    /// success; every failure is an auth error (never an internal one —
    /// an untrusted caller must not distinguish infra state from bad creds,
    /// except where the fetch itself failed, which is surfaced as Internal).
    pub async fn verify(&self, token: &str) -> Result<IdTokenClaims, ApiError> {
        let (header, payload, sig, signing_input) = split_jwt(token)?;
        let header: serde_json::Value =
            serde_json::from_slice(&header).map_err(|_| ApiError::Auth("malformed JWT".into()))?;
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Auth("JWT missing alg".into()))?;
        let claims: IdTokenClaims = serde_json::from_slice(&payload)
            .map_err(|_| ApiError::Auth("malformed JWT claims".into()))?;

        // iss must be a configured trusted issuer, and signatures only verify
        // against that issuer's keys.
        let trusted = self
            .issuers
            .iter()
            .find(|t| t.issuer == claims.iss)
            .ok_or_else(|| ApiError::Auth("untrusted issuer".into()))?;

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = claims.exp {
            if now + SKEW >= exp {
                return Err(ApiError::Auth("token has expired".into()));
            }
        }
        if let Some(nbf) = claims.nbf {
            if now + SKEW < nbf {
                return Err(ApiError::Auth("token not yet valid".into()));
            }
        }

        if let Some(aud) = trusted.audience.as_ref() {
            if !claims.aud.iter().any(|a| a == aud) {
                return Err(ApiError::Auth("token audience mismatch".into()));
            }
        }

        let jwks = self.jwks_for(&trusted.jwks_url).await?;
        verify_signature(&jwks, kid.as_deref(), alg, &sig, &signing_input)?;

        Ok(claims)
    }

    async fn jwks_for(&self, url: &str) -> Result<Arc<Jwks>, ApiError> {
        {
            let cache = self.cache.read().await;
            if let Some((jwks, at)) = cache.get(url) {
                if at.elapsed() < JWKS_TTL {
                    return Ok(Arc::new(jwks.clone()));
                }
            }
        }
        let jwks: Jwks = self
            .http
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| {
                tracing::error!(url = %url, error = %e, "JWKS fetch failed");
                ApiError::Internal("identity backend unavailable".into())
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!(url = %url, error = %e, "JWKS parse failed");
                ApiError::Internal("identity backend unavailable".into())
            })?;
        let arc = Arc::new(jwks);
        self.cache
            .write()
            .await
            .insert(url.to_owned(), ((*arc).clone(), Instant::now()));
        Ok(arc)
    }
}

/// Split a compact JWS into (header, payload, signature, signing_input).
fn split_jwt(token: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), ApiError> {
    let bad = || ApiError::Auth("malformed JWT".into());
    let mut parts = token.split('.');
    let h = parts.next().ok_or_else(bad)?;
    let p = parts.next().ok_or_else(bad)?;
    let s = parts.next().ok_or_else(bad)?;
    if parts.next().is_some() {
        return Err(bad());
    }
    let h = URL_SAFE_NO_PAD.decode(h).map_err(|_| bad())?;
    let p = URL_SAFE_NO_PAD.decode(p).map_err(|_| bad())?;
    let s = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad())?;
    // Signing input is ASCII "header.payload" — keep it as bytes directly.
    let si = token[..token.rfind('.').ok_or_else(bad)?]
        .as_bytes()
        .to_vec();
    Ok((h, p, s, si))
}

fn verify_signature(
    jwks: &Jwks,
    kid: Option<&str>,
    alg: &str,
    sig: &[u8],
    signing_input: &[u8],
) -> Result<(), ApiError> {
    let keys: Vec<&Jwk> = jwks
        .keys
        .iter()
        .filter(|k| match (kid, k.kid.as_deref()) {
            (Some(want), Some(have)) => want == have,
            // No kid in either: match on alg family.
            _ => true,
        })
        .filter(|k| k.alg.as_deref().map(|a| a == alg).unwrap_or(true))
        .collect();

    let mut saw_key = false;
    for key in keys {
        match (alg, key.kty.as_str()) {
            ("ES256", "EC") => {
                let (Some(x), Some(y), Some(crv)) = (&key.x, &key.y, &key.crv) else {
                    continue;
                };
                if crv != "P-256" {
                    continue;
                }
                saw_key = true;
                if verify_es256(x, y, sig, signing_input)? {
                    return Ok(());
                }
            }
            ("RS256", "RSA") => {
                let (Some(n), Some(e)) = (&key.n, &key.e) else {
                    continue;
                };
                saw_key = true;
                if verify_rs256(n, e, sig, signing_input) {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    if !saw_key {
        return Err(ApiError::Auth("no matching signing key".into()));
    }
    Err(ApiError::Auth("invalid signature".into()))
}

fn verify_es256(
    x_b64: &str,
    y_b64: &str,
    sig: &[u8],
    signing_input: &[u8],
) -> Result<bool, ApiError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let bad = || ApiError::Auth("malformed key material".into());
    let x = URL_SAFE_NO_PAD.decode(x_b64).map_err(|_| bad())?;
    let y = URL_SAFE_NO_PAD.decode(y_b64).map_err(|_| bad())?;
    if x.len() != 32 || y.len() != 32 {
        return Ok(false);
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(vk) => vk,
        Err(_) => return Ok(false),
    };
    let signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(vk.verify(signing_input, &signature).is_ok())
}

fn verify_rs256(n_b64: &str, e_b64: &str, sig: &[u8], signing_input: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;
    use rsa::BigUint;

    let n = match URL_SAFE_NO_PAD.decode(n_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let e = match URL_SAFE_NO_PAD.decode(e_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let pubkey =
        match rsa::RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)) {
            Ok(k) => k,
            Err(_) => return false,
        };
    let signature = match Signature::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    VerifyingKey::<Sha256>::new(pubkey)
        .verify(signing_input, &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rejects_garbage() {
        assert!(split_jwt("").is_err());
        assert!(split_jwt("a").is_err());
        assert!(split_jwt("a.b").is_err());
        assert!(split_jwt("a.b.c.d").is_err());
        assert!(split_jwt("!!..!!").is_err());
    }
}

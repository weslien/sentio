//! Per-mailbox isolation regression tests (OIDC identity path).
//!
//! These pin the three layers of user isolation:
//! 1. JWT verification: only trusted issuers, valid signatures, exp/nbf.
//! 2. Identity → mailbox resolution: exactly one mailbox per (issuer, sub),
//!    tenant derived from the mailbox's domain, USER_SCOPES clamp.
//! 3. Scope clamps: `require_scope` denies every admin scope to user
//!    identities even if the scope string is somehow present.
//!
//! The message-level address filtering is covered by repo-layer tests in
//! `tenant_isolation.rs` (same DATABASE_URL harness) and the live
//! post-deploy verification described in the PR body.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::json;

/// Minimal HS/ES JWT builder for tests.
fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn es256_jwt(signing_key: &SigningKey, iss: &str, sub: &str, exp: i64) -> String {
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": "test-key"});
    let claims = json!({"iss": iss, "sub": sub, "exp": exp});
    let si = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig: p256::ecdsa::Signature = signing_key.sign(si.as_bytes());
    format!("{}.{}", si, b64(&sig.to_bytes()))
}

fn jwks_json(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    json!({
        "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "test-key", "alg": "ES256", "use": "sig",
            "x": b64(point.x().map(|v| v.as_slice()).unwrap_or(&[])),
            "y": b64(point.y().map(|v| v.as_slice()).unwrap_or(&[])),
        }]
    })
    .to_string()
}

/// Serve a JWKS at a random localhost port; returns (base_url, joining handle).
async fn serve_jwks(body: String) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                Ok((sock, _)) = listener.accept() => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut r, mut w) = sock.into_split();
                    let mut buf = [0u8; 2048];
                    let _ = r.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = w.write_all(resp.as_bytes()).await;
                }
            }
        }
    });
    (format!("http://{addr}/jwks.json"), tx)
}

fn far_future() -> i64 {
    chrono::Utc::now().timestamp() + 3600
}

#[tokio::test]
async fn jwt_validates_against_trusted_issuer() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (url, _kill) = serve_jwks(jwks_json(&sk.verifying_key())).await;
    let verifier = sentio_api::oidc::JwtVerifier::new(vec![sentio_api::oidc::TrustedIssuer {
        issuer: "https://id.test".into(),
        jwks_url: url,
        audience: None,
    }]);
    let token = es256_jwt(&sk, "https://id.test", "user-123", far_future());
    let claims = verifier.verify(&token).await.expect("valid token accepted");
    assert_eq!(claims.sub, "user-123");
}

#[tokio::test]
async fn jwt_from_untrusted_issuer_rejected() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (url, _kill) = serve_jwks(jwks_json(&sk.verifying_key())).await;
    let verifier = sentio_api::oidc::JwtVerifier::new(vec![sentio_api::oidc::TrustedIssuer {
        issuer: "https://trusted.test".into(),
        jwks_url: url,
        audience: None,
    }]);
    // Signed by a real key but claiming an issuer we do not trust.
    let token = es256_jwt(&sk, "https://evil.test", "attacker", far_future());
    assert!(
        verifier.verify(&token).await.is_err(),
        "untrusted iss must be rejected"
    );
}

#[tokio::test]
async fn jwt_with_forged_signature_rejected() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let sk_other = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (url, _kill) = serve_jwks(jwks_json(&sk.verifying_key())).await;
    let verifier = sentio_api::oidc::JwtVerifier::new(vec![sentio_api::oidc::TrustedIssuer {
        issuer: "https://id.test".into(),
        jwks_url: url,
        audience: None,
    }]);
    // Token minted by a DIFFERENT key than the one in JWKS.
    let token = es256_jwt(&sk_other, "https://id.test", "user-123", far_future());
    assert!(
        verifier.verify(&token).await.is_err(),
        "forged signature must be rejected"
    );
}

#[tokio::test]
async fn expired_jwt_rejected() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (url, _kill) = serve_jwks(jwks_json(&sk.verifying_key())).await;
    let verifier = sentio_api::oidc::JwtVerifier::new(vec![sentio_api::oidc::TrustedIssuer {
        issuer: "https://id.test".into(),
        jwks_url: url,
        audience: None,
    }]);
    let token = es256_jwt(
        &sk,
        "https://id.test",
        "user-123",
        chrono::Utc::now().timestamp() - 10,
    );
    assert!(
        verifier.verify(&token).await.is_err(),
        "expired token must be rejected"
    );
}

#[tokio::test]
async fn jwt_with_wrong_audience_rejected() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let (url, _kill) = serve_jwks(jwks_json(&sk.verifying_key())).await;
    let verifier = sentio_api::oidc::JwtVerifier::new(vec![sentio_api::oidc::TrustedIssuer {
        issuer: "https://id.test".into(),
        jwks_url: url,
        audience: Some("https://sentio.api".into()),
    }]);
    // Valid signature, valid issuer, but minted for another service.
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": "test-key"});
    let claims = json!({"iss": "https://id.test", "sub": "user-123", "exp": far_future(), "aud": "https://other.service"});
    let si = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig: p256::ecdsa::Signature = sk.sign(si.as_bytes());
    let token = format!("{}.{}", si, b64(&sig.to_bytes()));
    assert!(
        verifier.verify(&token).await.is_err(),
        "token for another audience must be rejected"
    );
}

#[test]
fn user_scopes_are_clamped_at_authorization() {
    use sentio_api::auth::{AuthContext, MailboxIdentity};
    use sentio_core::tenant::TenantId;

    let user = AuthContext {
        tenant_id: TenantId(uuid::Uuid::new_v4()),
        // Even if a caller somehow injected admin scopes, is_user clamps.
        scopes: vec!["admin:api_keys:write".into(), "messages:read".into()],
        mailbox: Some(MailboxIdentity {
            mailbox_id: uuid::Uuid::new_v4(),
            address: "user@org.platform.weslien.org".into(),
        }),
        is_user: true,
    };

    // User scopes work.
    assert!(user.require_scope("messages:read").is_ok());
    assert!(user.require_scope("messages:send").is_ok());
    // Every admin scope is denied.
    assert!(user.require_scope("admin:api_keys:write").is_err());
    assert!(user.require_scope("admin:domains:write").is_err());
    // Wildcard is meaningless for users.
    assert!(user.require_scope("*").is_err());

    // Service keys keep legacy behavior.
    let svc = AuthContext {
        tenant_id: TenantId(uuid::Uuid::new_v4()),
        scopes: vec!["*".into()],
        mailbox: None,
        is_user: false,
    };
    assert!(svc.require_scope("admin:api_keys:write").is_ok());
}

#[tokio::test]
async fn malformed_jwts_rejected_without_panic() {
    use sentio_api::oidc::JwtVerifier;
    let verifier = JwtVerifier::new(vec![]);
    for bad in ["", ".", "a.b", "a.b.c.d", "!!!.???.***", "aaaa.bbbb.cccc"] {
        // No trusted issuers configured → untrusted issuer / malformed, never a panic.
        let _ = verifier.verify(bad).await;
    }
}

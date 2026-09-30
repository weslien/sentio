use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use sqlx::PgPool;

use sentio_core::config::SentioConfig;
use sentio_queue::Publisher;
use sentio_storage::S3BlobStore;
use sentio_store::RedisPool;

// ──────────────────────────────────────────────────────────────────────────────
// Application state
// ──────────────────────────────────────────────────────────────────────────────

pub type KeyedRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub publisher: Arc<Publisher>,
    pub blob_store: Arc<S3BlobStore>,
    pub config: Arc<SentioConfig>,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    /// Pre-auth limiter keyed by client IP; guards token brute force and
    /// unauthenticated endpoints.
    pub ip_rate_limiter: Arc<KeyedRateLimiter>,
    pub kv: Option<RedisPool>,
    /// Trusted-issuer OIDC verifier (platform identity tokens). Empty when
    /// no trusted issuers are configured — JWT bearer auth is then disabled
    /// and only Sentio API keys / Sentio OAuth tokens are accepted.
    pub oidc_verifier: Option<Arc<crate::oidc::JwtVerifier>>,
}

/// Requests allowed per client IP per minute before authentication.
const IP_LIMIT_PER_MINUTE: u32 = 120;

impl AppState {
    pub fn new(
        pool: PgPool,
        publisher: Publisher,
        blob_store: S3BlobStore,
        config: SentioConfig,
    ) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(600).unwrap());
        let rate_limiter = RateLimiter::dashmap(quota);
        let ip_quota = Quota::per_minute(NonZeroU32::new(IP_LIMIT_PER_MINUTE).unwrap());
        let ip_rate_limiter = RateLimiter::dashmap(ip_quota);

        let oidc_verifier = (!config.auth.oidc.trusted.is_empty()).then(|| {
            Arc::new(crate::oidc::JwtVerifier::new(
                config
                    .auth
                    .oidc
                    .trusted
                    .iter()
                    .map(|t| crate::oidc::TrustedIssuer {
                        issuer: t.issuer.clone(),
                        jwks_url: t.jwks_url.clone(),
                        audience: t.audience.clone(),
                    })
                    .collect(),
            ))
        });

        Self {
            pool,
            publisher: Arc::new(publisher),
            blob_store: Arc::new(blob_store),
            config: Arc::new(config),
            rate_limiter: Arc::new(rate_limiter),
            ip_rate_limiter: Arc::new(ip_rate_limiter),
            kv: None,
            oidc_verifier,
        }
    }

    pub fn with_kv(mut self, kv: RedisPool) -> Self {
        self.kv = Some(kv);
        self
    }

    /// Accessor for the OIDC verifier. Returns an empty verifier when OIDC
    /// is not configured, so callers need not branch on `Option`.
    pub fn oidc_verifier(&self) -> &crate::oidc::JwtVerifier {
        static EMPTY: std::sync::OnceLock<crate::oidc::JwtVerifier> = std::sync::OnceLock::new();
        self.oidc_verifier
            .as_deref()
            .unwrap_or_else(|| EMPTY.get_or_init(|| crate::oidc::JwtVerifier::new(vec![])))
    }
}

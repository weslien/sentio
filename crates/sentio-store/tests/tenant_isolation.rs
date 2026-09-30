//! Integration tests for cross-tenant isolation in the API-key, SMTP-
//! credential, and OAuth-client repositories.
//!
//! Regression tests for the IDOR family where route handlers passed only the
//! resource id and repository SQL had no tenant filter: an authenticated
//! admin of tenant A could revoke / delete / disable tenant B's resources by
//! enumerating UUIDs.
//!
//! Requires a live Postgres with migrations applied:
//! `DATABASE_URL=postgres://sentio:sentio@localhost:55432/sentio cargo test -p sentio-store`
//! Tests are skipped when DATABASE_URL is unset (unit-test runs, CI lint jobs).

use sentio_core::tenant::TenantId;
use sentio_core::traits::{
    ApiKeyRepository, InboundRouteRepository, MessageRepository, NewOAuthClient, NewSmtpCredential,
    OAuthClientRepository, SmtpCredentialRepository,
};
use sentio_store::postgres::{
    PgApiKeyRepository, PgInboundRouteRepository, PgMessageRepository, PgOAuthClientRepository,
    PgSmtpCredentialRepository,
};

async fn test_pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    match sqlx::PgPool::connect(&url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("cannot connect to DATABASE_URL ({e}); skipping");
            None
        }
    }
}

fn marker() -> String {
    // Unique per-test-run marker so parallel INSERTs don't collide with
    // pre-existing rows (username has a global UNIQUE constraint now).
    format!("tiso-{}", uuid::Uuid::new_v4())
}

async fn create_tenant(pool: &sqlx::PgPool) -> TenantId {
    let id = uuid::Uuid::new_v4();
    // Runtime (non-macro) query: this test target runs against a live
    // DATABASE_URL and is not part of the .sqlx offline cache.
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("iso-test-{}", id))
        .execute(pool)
        .await
        .expect("insert tenant");
    TenantId(id)
}

/// Removes the tenant row created by a test so repeated runs against the same
/// database don't accumulate fixtures. Lenient by design: cleanup failures
/// must not mask the actual assertion result (tests delete the entities they
/// created first; remaining children go with the tenant row via FK cascade).
async fn cleanup_tenant(pool: &sqlx::PgPool, tenant: TenantId) {
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant.0)
        .execute(pool)
        .await;
}

async fn create_smtp_credential(
    repo: &PgSmtpCredentialRepository,
    tenant: TenantId,
    username: String,
) -> Result<sentio_core::ids::SmtpCredentialId, sentio_core::error::SentioError> {
    repo.create(NewSmtpCredential {
        tenant_id: tenant,
        username,
        password_hash: "x".into(),
        mechanisms: vec!["PLAIN".into()],
        scram_stored_key: None,
        scram_server_key: None,
        scram_salt: None,
        scram_iterations: None,
    })
    .await
}

#[tokio::test]
async fn revoke_api_key_cannot_cross_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let repo_a = PgApiKeyRepository::new(pool.clone());
    let repo_b = PgApiKeyRepository::new(pool.clone());

    let key_b = repo_b
        .create(tenant_b, &format!("{m}-key"), &["messages:read".into()])
        .await
        .expect("create key for tenant B");

    // Tenant A's admin tries to revoke tenant B's key by id (the IDOR).
    let err = repo_a.revoke(tenant_a, key_b.id).await;
    assert!(
        err.is_err(),
        "tenant A must NOT be able to revoke tenant B's API key"
    );

    // The key must still exist for tenant B.
    let still = repo_b
        .list_by_tenant(tenant_b)
        .await
        .unwrap()
        .into_iter()
        .any(|k| k.id == key_b.id);
    assert!(
        still,
        "tenant B's key must survive tenant A's revoke attempt"
    );

    // Its own tenant CAN revoke it.
    repo_b
        .revoke(tenant_b, key_b.id)
        .await
        .expect("own-tenant revoke must succeed");
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

#[tokio::test]
async fn smtp_credential_mutations_cannot_cross_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let repo = PgSmtpCredentialRepository::new(pool.clone());

    let cred_b = create_smtp_credential(&repo, tenant_b, format!("{m}-agent"))
        .await
        .expect("create credential for tenant B");

    // Tenant A disables / deletes tenant B's credential by id (the IDOR).
    let disable = repo.update_enabled(tenant_a, cred_b, false).await;
    assert!(disable.is_err(), "cross-tenant disable must fail");

    let delete = repo.delete(tenant_a, cred_b).await;
    assert!(delete.is_err(), "cross-tenant delete must fail");

    // Credential still present and enabled for tenant B.
    let rec = repo.lookup(&format!("{m}-agent")).await.expect("lookup");
    assert!(rec.enabled, "credential must remain enabled");

    // Own tenant CAN mutate it.
    repo.update_enabled(tenant_b, cred_b, false)
        .await
        .expect("own-tenant disable must succeed");
    repo.delete(tenant_b, cred_b)
        .await
        .expect("own-tenant delete must succeed");
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

#[tokio::test]
async fn smtp_username_globally_unique_across_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let repo = PgSmtpCredentialRepository::new(pool.clone());

    create_smtp_credential(&repo, tenant_a, format!("{m}-dup"))
        .await
        .expect("first username insert");

    // Same username in a different tenant must now be rejected at the DB
    // level (global UNIQUE) — this is what prevents SMTP AUTH from ever
    // resolving a username ambiguously across tenants.
    let dup = create_smtp_credential(&repo, tenant_b, format!("{m}-dup")).await;
    assert!(
        dup.is_err(),
        "duplicate username across tenants must be rejected"
    );

    // Cleanup.
    let id_a = repo.lookup(&format!("{m}-dup")).await.unwrap().id;
    repo.delete(tenant_a, id_a).await.unwrap();
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

#[tokio::test]
async fn oauth_client_mutations_cannot_cross_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let repo = PgOAuthClientRepository::new(pool.clone());

    let client_b = repo
        .create(NewOAuthClient {
            tenant_id: tenant_b,
            client_id: format!("{m}-client"),
            client_secret_hash: "x".into(),
            name: format!("{m} client"),
            redirect_uris: vec!["https://example.org/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["read".into()],
        })
        .await
        .expect("create oauth client for tenant B");

    // Tenant A revokes / deletes tenant B's client by id (the IDOR).
    let revoke = repo.revoke(tenant_a, client_b).await;
    assert!(revoke.is_err(), "cross-tenant revoke must fail");

    let delete = repo.delete(tenant_a, client_b).await;
    assert!(delete.is_err(), "cross-tenant delete must fail");

    // Own tenant CAN.
    repo.revoke(tenant_b, client_b)
        .await
        .expect("own-tenant revoke must succeed");
    repo.delete(tenant_b, client_b)
        .await
        .expect("own-tenant delete must succeed");
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

// NOTE (handler-layer coverage): the create-IDOR family found in review —
// create_api_key / create_smtp_credential minting resources under the
// client-controlled path tenant — is closed by the `ensure_tenant_match`
// handler guard (404 unless path tenant == auth.tenant_id), which is
// exercised by the live post-deploy verification (two tenants, mismatched
// path, expect 404) rather than by these repo-layer tests.

#[tokio::test]
async fn api_key_create_scopes_to_explicit_tenant() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    // "Attacker" creates a key naming tenant B as the target.
    // create() is explicit (not path-derived) at the repo layer; the
    // handler guard is what prevents cross-tenant creation. Repo layer
    // must still bind the key to the tenant it is told — i.e. there is
    // no implicit "current tenant" the handler could have meant.
    let created_b = PgApiKeyRepository::new(pool.clone())
        .create(
            tenant_b,
            &format!("{m}-created-for-b"),
            &["messages:read".into()],
        )
        .await
        .expect("create");

    // The key must list under tenant B, never tenant A.
    let in_a = PgApiKeyRepository::new(pool.clone())
        .list_by_tenant(tenant_a)
        .await
        .unwrap()
        .iter()
        .any(|k| k.id == created_b.id);
    assert!(
        !in_a,
        "key created for tenant B must not list under tenant A"
    );

    let in_b = PgApiKeyRepository::new(pool.clone())
        .list_by_tenant(tenant_b)
        .await
        .unwrap()
        .iter()
        .any(|k| k.id == created_b.id);
    assert!(in_b, "key created for tenant B must list under tenant B");

    // Cleanup.
    PgApiKeyRepository::new(pool.clone())
        .revoke(tenant_b, created_b.id)
        .await
        .unwrap();
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

// ── Inbound routes ────────────────────────────────────────────────────────────

async fn create_inbound_route(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    pattern: &str,
) -> sentio_core::ids::InboundRouteId {
    use sentio_core::inbound::InboundRouteMatchType;
    use sentio_core::traits::NewInboundRoute;
    let repo = PgInboundRouteRepository::new(pool.clone());
    repo.create(NewInboundRoute {
        tenant_id: tenant,
        pattern: pattern.into(),
        match_type: InboundRouteMatchType::Exact,
        webhook_url: format!("https://{pattern}.example/hook"),
        priority: 1,
        llm_classify: false,
        auto_respond: false,
        auto_respond_config: None,
    })
    .await
    .expect("create inbound route")
}

#[tokio::test]
async fn inbound_route_update_cannot_cross_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let route_b = create_inbound_route(&pool, tenant_b, &format!("{m}-b")).await;
    let repo = PgInboundRouteRepository::new(pool.clone());

    use sentio_core::inbound::InboundRouteMatchType;
    use sentio_core::traits::InboundRouteUpdate;

    // Tenant A tries to rewrite tenant B's route (the IDOR).
    let err = repo
        .update(
            tenant_a,
            route_b,
            InboundRouteUpdate {
                pattern: format!("{m}-hijacked"),
                match_type: InboundRouteMatchType::Exact,
                webhook_url: "https://attacker.example/hook".into(),
                priority: 99,
                llm_classify: false,
                auto_respond: false,
                auto_respond_config: None,
            },
        )
        .await;
    assert!(
        err.is_err(),
        "tenant A must NOT be able to update tenant B's inbound route"
    );

    // B's route is untouched.
    let record = repo.get(route_b).await.expect("route still readable");
    assert_eq!(
        record.pattern,
        format!("{m}-b"),
        "pattern must be unchanged"
    );
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

#[tokio::test]
async fn inbound_route_delete_cannot_cross_tenants() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant_a = create_tenant(&pool).await;
    let tenant_b = create_tenant(&pool).await;
    let m = marker();

    let route_b = create_inbound_route(&pool, tenant_b, &format!("{m}-del")).await;
    let repo = PgInboundRouteRepository::new(pool.clone());

    // Tenant A tries to delete tenant B's route (the IDOR).
    let err = repo.delete(tenant_a, route_b).await;
    assert!(
        err.is_err(),
        "tenant A must NOT be able to delete tenant B's inbound route"
    );

    // B can still see and delete its own route.
    let record = repo.get(route_b).await.expect("route still exists");
    assert_eq!(record.tenant_id, tenant_b);
    repo.delete(tenant_b, route_b)
        .await
        .expect("own delete works");
    cleanup_tenant(&pool, tenant_a).await;
    cleanup_tenant(&pool, tenant_b).await;
}

// ── Mailbox isolation (message address filter) ─────────────────────────────────

#[tokio::test]
async fn message_list_address_filter_returns_only_own_mail() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let tenant = create_tenant(&pool).await;
    let m = marker();

    // One domain for the tenant (required by messages FK).
    let _ = sqlx::query("INSERT INTO domains (id, tenant_id, domain_name, use_for_receiving, use_for_sending, status, verification_token) VALUES ($1, $2, $3, true, true, 'verified', $4)")
        .bind(uuid::Uuid::new_v4())
        .bind(tenant.0)
        .bind(format!("{m}.example"))
        .bind(format!("tok-{m}"))
        .execute(&pool)
        .await
        .expect("insert domain");

    let insert_message = |envelope_to: Vec<String>, header_to: Vec<String>| {
        let pool = pool.clone();
        let tenant = tenant.0;
        let m = m.clone();
        async move {
            let id = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO messages (id, tenant_id, direction, envelope_from, envelope_to, header_to, status) \
                 VALUES ($1, $2, 'inbound', 'outside@example', $3, $4, 'delivered')",
            )
            .bind(id)
            .bind(tenant)
            .bind(envelope_to)
            .bind(header_to)
            .execute(&pool)
            .await
            .expect("insert message");
            id
        }
    };

    // alice's mail, bob's mail, mail to both.
    let _alice = insert_message(
        vec![format!("alice@{m}.example")],
        vec![format!("alice@{m}.example")],
    )
    .await;
    let _bob = insert_message(
        vec![format!("bob@{m}.example")],
        vec![format!("bob@{m}.example")],
    )
    .await;
    let _both = insert_message(
        vec![format!("alice@{m}.example"), format!("bob@{m}.example")],
        vec![format!("alice@{m}.example")],
    )
    .await;

    let repo = PgMessageRepository::new(pool.clone());
    let records = repo
        .list(
            tenant,
            sentio_core::traits::MessageFilter {
                status: None,
                direction: None,
                from: chrono::Utc::now() - chrono::Duration::hours(24),
                to: chrono::Utc::now() + chrono::Duration::hours(1),
                limit: 100,
                offset: 0,
                address: Some(format!("alice@{m}.example")),
            },
        )
        .await
        .expect("list with address filter");

    let bob_mail = records.iter().any(|r| {
        r.envelope_to.iter().any(|a| a.contains("bob@"))
            && !r.envelope_to.iter().any(|a| a.contains("alice"))
    });
    assert!(!bob_mail, "alice's view must not include bob-only mail");
    assert_eq!(
        records.len(),
        2,
        "alice sees exactly her mail + shared mail, not bob's"
    );

    cleanup_tenant(&pool, tenant).await;
}

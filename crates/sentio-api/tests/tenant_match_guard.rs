//! Handler-layer tenant guard, pinned at unit level (review finding: the
//! repo-layer isolation tests cannot catch a handler reverting to the
//! client-controlled path tenant). Full axum wiring requires live
//! infrastructure (pool + nats + s3), so the guard's contract is asserted
//! here, and end-to-end two-tenant behavior is verified against the deployed
//! service (see PR description: cross-tenant = 404, own tenant = 200).

use axum::http::StatusCode;
use axum::response::IntoResponse;
use sentio_api::auth::AuthContext;
use sentio_api::routes::ensure_tenant_match;
use sentio_core::tenant::TenantId;

fn ctx_for(tenant: uuid::Uuid) -> AuthContext {
    AuthContext {
        tenant_id: TenantId(tenant),
        scopes: vec![],
    }
}

#[test]
fn guard_passes_when_path_tenant_matches_session() {
    let t = uuid::Uuid::new_v4();
    assert!(ensure_tenant_match(&ctx_for(t), t).is_ok());
}

#[test]
fn guard_rejects_mismatched_path_tenant_with_not_found() {
    let session = uuid::Uuid::new_v4();
    let attacker_path = uuid::Uuid::new_v4();
    let err = ensure_tenant_match(&ctx_for(session), attacker_path)
        .expect_err("mismatched path tenant must be rejected");
    // Must serialize as 404 (not 403): the existence of another tenant's
    // resources must not leak through the error code.
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

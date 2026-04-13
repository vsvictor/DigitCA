use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use digitca::{
    api::{AppState, router},
    error::AppResult,
    ldap_auth::Authorizer,
    ldap_publish::LdapPublisher,
    service::CaService,
    storage::{CaRepository, InMemoryStorage},
};
use http_body_util::BodyExt;
use openssl::x509::{CrlStatus, ReasonCode, X509, X509Crl};
use serde_json::{Value, json};
use tower::util::ServiceExt;

struct AllowAuthorizer;

#[async_trait]
impl Authorizer for AllowAuthorizer {
    async fn authorize(&self, _username: &str, _password: &str) -> AppResult<()> {
        Ok(())
    }
}

fn basic_auth(username: &str, password: &str) -> String {
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {encoded}")
}

fn test_app() -> axum::Router {
    let storage: Box<dyn CaRepository + Send + Sync> = Box::new(InMemoryStorage::default());
    let service = CaService::new(storage, Some("test-passphrase".to_string()), None);

    let state = AppState {
        service: Arc::new(service),
        ldap: Arc::new(AllowAuthorizer),
        publisher: LdapPublisher::disabled(),
    };

    router(state)
}

async fn json_response(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.expect("body collect must succeed").to_bytes();
    serde_json::from_slice(&bytes).expect("json parse must succeed")
}

#[tokio::test]
async fn issue_returns_key_but_get_and_list_hide_it() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_resp = app.clone().oneshot(init_req).await.expect("response must succeed");
    assert_eq!(init_resp.status(), StatusCode::CREATED);

    let issue_req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "common_name":"service.internal",
                "profile":"server-tls",
                "issuer":"root",
                "dns_names":["service.internal"],
                "ip_sans":[],
                "validity_days":90
            })
            .to_string(),
        ))
        .expect("request must be built");

    let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
    assert_eq!(issue_resp.status(), StatusCode::CREATED);
    let issue_json = json_response(issue_resp).await;

    let serial = issue_json["serial"].as_str().expect("serial must be present").to_string();
    assert!(issue_json.get("key_pem").is_some());
    assert!(issue_json["key_pem"].as_str().unwrap_or("").contains("BEGIN PRIVATE KEY"));

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/certificates/{serial}"))
        .header(AUTHORIZATION, auth.clone())
        .body(Body::empty())
        .expect("request must be built");
    let get_resp = app.clone().oneshot(get_req).await.expect("response must succeed");
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_json = json_response(get_resp).await;
    assert!(get_json.get("key_pem").is_none());

    let list_req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates?include_revoked=false&page=1&per_page=10")
        .header(AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request must be built");
    let list_resp = app.clone().oneshot(list_req).await.expect("response must succeed");
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json = json_response(list_resp).await;
    assert_eq!(list_json["total"].as_u64(), Some(1));
    assert!(list_json["data"].as_array().expect("data must be array")[0].get("key_pem").is_none());
}

#[tokio::test]
async fn list_supports_pagination() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_resp = app.clone().oneshot(init_req).await.expect("response must succeed");
    assert_eq!(init_resp.status(), StatusCode::CREATED);

    for cn in ["service-a.internal", "service-b.internal"] {
        let issue_req = Request::builder()
            .method("POST")
            .uri("/api/v1/certificates")
            .header(AUTHORIZATION, auth.clone())
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "common_name":cn,
                    "profile":"server-tls",
                    "issuer":"root",
                    "dns_names":[cn],
                    "ip_sans":[],
                    "validity_days":90
                })
                .to_string(),
            ))
            .expect("request must be built");
        let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
        assert_eq!(issue_resp.status(), StatusCode::CREATED);
    }

    let list_req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates?include_revoked=false&page=2&per_page=1")
        .header(AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request must be built");
    let list_resp = app.clone().oneshot(list_req).await.expect("response must succeed");
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json = json_response(list_resp).await;

    assert_eq!(list_json["total"].as_u64(), Some(2));
    assert_eq!(list_json["page"].as_u64(), Some(2));
    assert_eq!(list_json["per_page"].as_u64(), Some(1));
    assert_eq!(list_json["data"].as_array().map(|a| a.len()), Some(1));
}

#[tokio::test]
async fn chain_endpoint_returns_pem_bundle() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_resp = app.clone().oneshot(init_req).await.expect("response must succeed");
    assert_eq!(init_resp.status(), StatusCode::CREATED);

    let issue_req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "common_name":"chain.internal",
                "profile":"server-tls",
                "issuer":"root",
                "dns_names":["chain.internal"],
                "ip_sans":[],
                "validity_days":90
            })
            .to_string(),
        ))
        .expect("request must be built");
    let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
    let issue_json = json_response(issue_resp).await;
    let serial = issue_json["serial"].as_str().expect("serial must be present");

    let chain_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/certificates/{serial}/chain"))
        .header(AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request must be built");
    let chain_resp = app.oneshot(chain_req).await.expect("response must succeed");
    assert_eq!(chain_resp.status(), StatusCode::OK);
    let chain_json = json_response(chain_resp).await;

    let pem = chain_json["pem"].as_str().expect("pem must be present");
    assert!(pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn unauthorized_request_is_rejected() {
    let app = test_app();

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .body(Body::empty())
        .expect("request must be built");

    let resp = app.oneshot(req).await.expect("response must succeed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_with_invalid_reason_returns_422() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_resp = app.clone().oneshot(init_req).await.expect("response must succeed");
    assert_eq!(init_resp.status(), StatusCode::CREATED);

    let issue_req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "common_name":"bad-reason.internal",
                "profile":"server-tls",
                "issuer":"root",
                "dns_names":["bad-reason.internal"],
                "ip_sans":[],
                "validity_days":90
            })
            .to_string(),
        ))
        .expect("request must be built");
    let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
    assert_eq!(issue_resp.status(), StatusCode::CREATED);
    let issue_json = json_response(issue_resp).await;
    let serial = issue_json["serial"].as_str().expect("serial must be present");

    let revoke_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/certificates/{serial}/revoke"))
        .header(AUTHORIZATION, auth)
        .header("content-type", "application/json")
        .body(Body::from(json!({"reason":"somethingInvalid"}).to_string()))
        .expect("request must be built");

    let revoke_resp = app.oneshot(revoke_req).await.expect("response must succeed");
    assert_eq!(revoke_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn crl_endpoints_return_expected_statuses() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_resp = app.clone().oneshot(init_req).await.expect("response must succeed");
    assert_eq!(init_resp.status(), StatusCode::CREATED);

    let issue_req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "common_name":"crl-reason.internal",
                "profile":"server-tls",
                "issuer":"root",
                "dns_names":["crl-reason.internal"],
                "ip_sans":[],
                "validity_days":90
            })
            .to_string(),
        ))
        .expect("request must be built");
    let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
    assert_eq!(issue_resp.status(), StatusCode::CREATED);
    let issue_json = json_response(issue_resp).await;
    let cert_pem = issue_json["cert_pem"].as_str().expect("cert_pem must be present");

    let serial = issue_json["serial"].as_str().expect("serial must be present");
    let revoke_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/certificates/{serial}/revoke"))
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"reason":"keyCompromise"}).to_string()))
        .expect("request must be built");
    let revoke_resp = app.clone().oneshot(revoke_req).await.expect("response must succeed");
    assert_eq!(revoke_resp.status(), StatusCode::OK);

    let root_req = Request::builder()
        .method("GET")
        .uri("/crl/root.crl")
        .header(AUTHORIZATION, auth.clone())
        .body(Body::empty())
        .expect("request must be built");
    let root_resp = app.clone().oneshot(root_req).await.expect("response must succeed");
    let root_status = root_resp.status();
    let root_json = json_response(root_resp).await;
    assert_eq!(root_status, StatusCode::OK, "неочікувана відповідь root CRL: {root_json:?}");
    let root_crl_pem = root_json["pem"].as_str().expect("pem must be present");
    assert!(root_crl_pem.contains("BEGIN X509 CRL"));

    let crl = X509Crl::from_pem(root_crl_pem.as_bytes()).expect("CRL must parse from PEM");
    let cert = X509::from_pem(cert_pem.as_bytes()).expect("certificate must parse from PEM");
    match crl.get_by_serial(cert.serial_number()) {
        CrlStatus::Revoked(rev) => {
            let (_, reason) = rev
                .extension::<ReasonCode>()
                .expect("reasonCode read must succeed")
                .expect("reasonCode extension must exist");
            assert_eq!(reason.get_i64().expect("reason code must decode"), 1);
        }
        _ => panic!("сертифікат має бути у CRL зі статусом Revoked"),
    }

    let int_req = Request::builder()
        .method("GET")
        .uri("/crl/intermediate.crl")
        .header(AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request must be built");
    let int_resp = app.oneshot(int_req).await.expect("response must succeed");
    assert_eq!(int_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn intermediate_crl_contains_only_intermediate_revocations() {
    let app = test_app();
    let auth = basic_auth("admin", "secret");

    let init_root_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/root")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"common_name":"DigitCA Test Root","validity_days":365}).to_string()))
        .expect("request must be built");
    let init_root_resp = app.clone().oneshot(init_root_req).await.expect("response must succeed");
    assert_eq!(init_root_resp.status(), StatusCode::CREATED);

    let init_int_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ca/intermediate")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"common_name":"DigitCA Test Intermediate","validity_days":365}).to_string(),
        ))
        .expect("request must be built");
    let init_int_resp = app.clone().oneshot(init_int_req).await.expect("response must succeed");
    assert_eq!(init_int_resp.status(), StatusCode::CREATED);

    let issue_req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "common_name":"int-only.internal",
                "profile":"server-tls",
                "issuer":"intermediate",
                "dns_names":["int-only.internal"],
                "ip_sans":[],
                "validity_days":90
            })
            .to_string(),
        ))
        .expect("request must be built");
    let issue_resp = app.clone().oneshot(issue_req).await.expect("response must succeed");
    assert_eq!(issue_resp.status(), StatusCode::CREATED);
    let issue_json = json_response(issue_resp).await;
    let cert_pem = issue_json["cert_pem"].as_str().expect("cert_pem must be present");
    let serial = issue_json["serial"].as_str().expect("serial must be present");

    let revoke_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/certificates/{serial}/revoke"))
        .header(AUTHORIZATION, auth.clone())
        .header("content-type", "application/json")
        .body(Body::from(json!({"reason":"caCompromise"}).to_string()))
        .expect("request must be built");
    let revoke_resp = app.clone().oneshot(revoke_req).await.expect("response must succeed");
    assert_eq!(revoke_resp.status(), StatusCode::OK);

    let int_crl_req = Request::builder()
        .method("GET")
        .uri("/crl/intermediate.crl")
        .header(AUTHORIZATION, auth.clone())
        .body(Body::empty())
        .expect("request must be built");
    let int_crl_resp = app.clone().oneshot(int_crl_req).await.expect("response must succeed");
    assert_eq!(int_crl_resp.status(), StatusCode::OK);
    let int_crl_json = json_response(int_crl_resp).await;
    let int_crl_pem = int_crl_json["pem"].as_str().expect("pem must be present");

    let cert = X509::from_pem(cert_pem.as_bytes()).expect("certificate must parse from PEM");
    let int_crl = X509Crl::from_pem(int_crl_pem.as_bytes()).expect("intermediate CRL must parse");
    match int_crl.get_by_serial(cert.serial_number()) {
        CrlStatus::Revoked(rev) => {
            let (_, reason) = rev
                .extension::<ReasonCode>()
                .expect("reasonCode read must succeed")
                .expect("reasonCode extension must exist");
            assert_eq!(reason.get_i64().expect("reason code must decode"), 2);
        }
        _ => panic!("сертифікат має бути присутній у intermediate CRL"),
    }

    let root_crl_req = Request::builder()
        .method("GET")
        .uri("/crl/root.crl")
        .header(AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request must be built");
    let root_crl_resp = app.oneshot(root_crl_req).await.expect("response must succeed");
    assert_eq!(root_crl_resp.status(), StatusCode::OK);
    let root_crl_json = json_response(root_crl_resp).await;
    let root_crl_pem = root_crl_json["pem"].as_str().expect("pem must be present");
    let root_crl = X509Crl::from_pem(root_crl_pem.as_bytes()).expect("root CRL must parse");
    assert!(matches!(root_crl.get_by_serial(cert.serial_number()), CrlStatus::NotRevoked));
}









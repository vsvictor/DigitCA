use std::{collections::HashMap, env, os::raw::{c_int, c_ulong}, ptr, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use digitca::{
    error::{AppError, AppResult},
    models::{CertStatus, IssuerKind, RevocationRecord},
    storage::{CaRepository, MongoStorage},
};
use dotenvy::dotenv;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    asn1::{Asn1IntegerRef, Asn1Time},
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspRequest, OcspResponse, OcspResponseStatus},
    pkey::{PKey, Private},
    x509::X509,
};
use openssl_sys as ffi;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

unsafe extern "C" {
    fn OCSP_request_onereq_count(req: *const ffi::OCSP_REQUEST) -> c_int;
    fn OCSP_request_onereq_get0(req: *const ffi::OCSP_REQUEST, i: c_int) -> *mut ffi::OCSP_ONEREQ;
    fn OCSP_onereq_get0_id(one: *const ffi::OCSP_ONEREQ) -> *mut ffi::OCSP_CERTID;
    fn OCSP_id_get0_info(
        pi_name_hash: *mut *mut ffi::ASN1_OCTET_STRING,
        pmd: *mut *mut ffi::ASN1_OBJECT,
        pi_key_hash: *mut *mut ffi::ASN1_OCTET_STRING,
        pserial: *mut *mut ffi::ASN1_INTEGER,
        cid: *mut ffi::OCSP_CERTID,
    ) -> c_int;
    fn OCSP_id_cmp(a: *const ffi::OCSP_CERTID, b: *const ffi::OCSP_CERTID) -> c_int;
    fn OCSP_basic_add1_status(
        rsp: *mut ffi::OCSP_BASICRESP,
        cid: *mut ffi::OCSP_CERTID,
        status: c_int,
        reason: c_int,
        revtime: *mut ffi::ASN1_TIME,
        thisupd: *mut ffi::ASN1_TIME,
        nextupd: *mut ffi::ASN1_TIME,
    ) -> *mut OcspSingleResp;
    fn OCSP_basic_sign(
        brsp: *mut ffi::OCSP_BASICRESP,
        signer: *mut ffi::X509,
        key: *mut ffi::EVP_PKEY,
        dgst: *const ffi::EVP_MD,
        certs: *mut ffi::stack_st_X509,
        flags: c_ulong,
    ) -> c_int;
    fn OCSP_CERTID_dup(id: *const ffi::OCSP_CERTID) -> *mut ffi::OCSP_CERTID;
}

enum OcspSingleResp {}

#[derive(Clone, Debug)]
pub struct OcspConfig {
    pub mongodb_uri: String,
    pub mongodb_db: String,
    pub bind: String,
    pub port: u16,
    pub root_ca_key_passphrase: Option<String>,
    pub intermediate_ca_key_passphrase: Option<String>,
    pub next_update_seconds: u32,
}

impl OcspConfig {
    pub fn from_env() -> AppResult<Self> {
        Ok(Self {
            mongodb_uri: must_get("MONGODB_URI")?,
            mongodb_db: must_get("MONGODB_DB")?,
            bind: env::var("OCSP_BIND")
                .or_else(|_| env::var("HTTP_BIND"))
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("OCSP_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(8082),
            root_ca_key_passphrase: env::var("ROOT_CA_KEY_PASSPHRASE").ok(),
            intermediate_ca_key_passphrase: env::var("INTERMEDIATE_CA_KEY_PASSPHRASE")
                .ok()
                .or_else(|| env::var("ROOT_CA_KEY_PASSPHRASE").ok()),
            next_update_seconds: env::var("OCSP_NEXT_UPDATE_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(3600),
        })
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignerKind {
    Root,
    Intermediate,
}

#[derive(Debug)]
enum EntryStatus {
    Good,
    Revoked { revoked_at: DateTime<Utc>, reason_code: c_int },
    Unknown,
}

struct RequestEntry {
    cert_id: OcspCertId,
    issuer_hint: Option<SignerKind>,
    status: EntryStatus,
}

struct ParsedRequestEntry {
    cert_id: OcspCertId,
    serial: String,
}

struct SignerMaterial {
    cert: X509,
    key: PKey<Private>,
}

struct Issuers {
    root_cert: X509,
    root_key_pem: String,
    root_key_encrypted: bool,
    intermediate_cert: Option<X509>,
    intermediate_key_pem: Option<String>,
    intermediate_key_encrypted: bool,
}

pub struct OcspResponder {
    repository: Box<dyn CaRepository + Send + Sync>,
    root_ca_key_passphrase: Option<String>,
    intermediate_ca_key_passphrase: Option<String>,
    next_update_seconds: u32,
}

impl OcspResponder {
    pub fn new(
        repository: Box<dyn CaRepository + Send + Sync>,
        root_ca_key_passphrase: Option<String>,
        intermediate_ca_key_passphrase: Option<String>,
        next_update_seconds: u32,
    ) -> Self {
        Self {
            repository,
            root_ca_key_passphrase,
            intermediate_ca_key_passphrase,
            next_update_seconds,
        }
    }

    pub async fn respond_der(&self, request_der: &[u8]) -> Vec<u8> {
        match self.build_response_der(request_der).await {
            Ok(der) => der,
            Err(err) => {
                tracing::error!("OCSP internal error: {err}");
                match build_status_only_response(OcspResponseStatus::INTERNAL_ERROR) {
                    Ok(der) => der,
                    Err(fallback_err) => {
                        tracing::error!("failed to build OCSP INTERNAL_ERROR response: {fallback_err}");
                        Vec::new()
                    }
                }
            }
        }
    }

    async fn build_response_der(&self, request_der: &[u8]) -> AppResult<Vec<u8>> {
        let request = match OcspRequest::from_der(request_der) {
            Ok(request) => request,
            Err(_) => return build_status_only_response(OcspResponseStatus::MALFORMED_REQUEST),
        };

        let parsed_entries = parse_request_entries(&request)?;
        let entries = self.resolve_request_entries(parsed_entries).await?;
        if entries.is_empty() {
            return build_status_only_response(OcspResponseStatus::MALFORMED_REQUEST);
        }

        let issuers = self.load_issuers().await?;
        let signer_kind = choose_signer_kind(&entries, issuers.intermediate_cert.is_some())
            .ok_or_else(|| AppError::Validation("OCSP request mixes certificates from different issuers".to_string()))?;
        let signer = self.build_signer(&issuers, signer_kind)?;

        self.sign_success_response(entries, signer)
    }

    async fn load_issuers(&self) -> AppResult<Issuers> {
        let root = self
            .repository
            .get_root()
            .await?
            .ok_or_else(|| AppError::NotFound("root CA not initialized".to_string()))?;
        let root_cert = X509::from_pem(root.cert_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;

        let intermediate = self.repository.get_intermediate().await?;
        let (intermediate_cert, intermediate_key_pem, intermediate_key_encrypted) =
            if let Some(intermediate) = intermediate {
                let cert = X509::from_pem(intermediate.cert_pem.as_bytes())
                    .map_err(|e| AppError::Crypto(e.to_string()))?;
                (Some(cert), Some(intermediate.key_pem), intermediate.key_encrypted)
            } else {
                (None, None, false)
            };

        Ok(Issuers {
            root_cert,
            root_key_pem: root.key_pem,
            root_key_encrypted: root.key_encrypted,
            intermediate_cert,
            intermediate_key_pem,
            intermediate_key_encrypted,
        })
    }

    fn build_signer(&self, issuers: &Issuers, signer_kind: SignerKind) -> AppResult<SignerMaterial> {
        match signer_kind {
            SignerKind::Root => {
                let key = load_private_key(
                    &issuers.root_key_pem,
                    issuers.root_key_encrypted,
                    self.root_ca_key_passphrase.as_deref(),
                    "root",
                )?;
                Ok(SignerMaterial {
                    cert: issuers.root_cert.clone(),
                    key,
                })
            }
            SignerKind::Intermediate => {
                let cert = issuers
                    .intermediate_cert
                    .as_ref()
                    .ok_or_else(|| AppError::NotFound("intermediate CA not initialized".to_string()))?
                    .clone();
                let key_pem = issuers
                    .intermediate_key_pem
                    .as_ref()
                    .ok_or_else(|| AppError::NotFound("intermediate CA key is missing".to_string()))?;

                let key = load_private_key(
                    key_pem,
                    issuers.intermediate_key_encrypted,
                    self.intermediate_ca_key_passphrase.as_deref(),
                    "intermediate",
                )?;

                Ok(SignerMaterial { cert, key })
            }
        }
    }

    async fn resolve_request_entries(
        &self,
        parsed_entries: Vec<ParsedRequestEntry>,
    ) -> AppResult<Vec<RequestEntry>> {
        let issuers = self.load_issuers().await?;
        let revocations = self.repository.list_revocations().await?;
        let revocation_index = build_revocation_index(revocations);

        let mut entries = Vec::new();

        for parsed in parsed_entries {
            let cert = self.repository.get_certificate(&parsed.serial).await?;

            if let Some(cert) = cert {
                    let issuer_kind = map_issuer_kind(cert.issuer_kind.as_ref());
                    let issuer_cert = match issuer_kind {
                        SignerKind::Root => issuers.root_cert.clone(),
                        SignerKind::Intermediate => issuers
                            .intermediate_cert
                            .as_ref()
                            .ok_or_else(|| AppError::NotFound("intermediate CA not initialized".to_string()))?
                            .clone(),
                    };

                    let leaf = X509::from_pem(cert.cert_pem.as_bytes())
                        .map_err(|e| AppError::Crypto(e.to_string()))?;
                    let expected_id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &issuer_cert)
                        .map_err(|e| AppError::Crypto(e.to_string()))?;

                    if unsafe { OCSP_id_cmp(expected_id.as_ptr(), parsed.cert_id.as_ptr()) } != 0 {
                        entries.push(RequestEntry {
                            cert_id: parsed.cert_id,
                            issuer_hint: None,
                            status: EntryStatus::Unknown,
                        });
                        continue;
                    }

                    let status = if cert.status == CertStatus::Revoked {
                        if let Some(rev) = revocation_index.get(&normalize_serial(&cert.serial)) {
                            EntryStatus::Revoked {
                                revoked_at: rev.revoked_at,
                                reason_code: map_reason_code(&rev.reason),
                            }
                        } else {
                            EntryStatus::Revoked {
                                revoked_at: Utc::now(),
                                reason_code: ffi::OCSP_REVOKED_STATUS_UNSPECIFIED,
                            }
                        }
                    } else {
                        EntryStatus::Good
                    };

                    entries.push(RequestEntry {
                        cert_id: parsed.cert_id,
                        issuer_hint: Some(issuer_kind),
                        status,
                    });
            } else {
                entries.push(RequestEntry {
                    cert_id: parsed.cert_id,
                    issuer_hint: None,
                    status: EntryStatus::Unknown,
                });
            }
        }

        Ok(entries)
    }

    fn sign_success_response(&self, entries: Vec<RequestEntry>, signer: SignerMaterial) -> AppResult<Vec<u8>> {
        let now = Utc::now();
        let this_update = Asn1Time::from_unix(now.timestamp()).map_err(|e| AppError::Crypto(e.to_string()))?;
        let next_update = Asn1Time::from_unix(now.timestamp() + i64::from(self.next_update_seconds))
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        // SAFETY: All pointers are owned/valid for the duration of the call sequence and OpenSSL
        // takes ownership of the OCSP_BASICRESP once wrapped into OCSP_RESPONSE.
        unsafe {
            let basic = ffi::OCSP_BASICRESP_new();
            if basic.is_null() {
                return Err(AppError::Crypto("failed to create OCSP basic response".to_string()));
            }

            for entry in &entries {
                let (status, reason, revocation_ptr_holder) = match &entry.status {
                    EntryStatus::Good => (ffi::V_OCSP_CERTSTATUS_GOOD, ffi::OCSP_REVOKED_STATUS_NOSTATUS, None),
                    EntryStatus::Unknown => {
                        (ffi::V_OCSP_CERTSTATUS_UNKNOWN, ffi::OCSP_REVOKED_STATUS_NOSTATUS, None)
                    }
                    EntryStatus::Revoked {
                        revoked_at,
                        reason_code,
                    } => {
                        let rev_time = Asn1Time::from_unix(revoked_at.timestamp())
                            .map_err(|e| AppError::Crypto(e.to_string()))?;
                        (ffi::V_OCSP_CERTSTATUS_REVOKED, *reason_code, Some(rev_time))
                    }
                };

                let revocation_ptr = revocation_ptr_holder
                    .as_ref()
                    .map(|value| value.as_ptr())
                    .unwrap_or(ptr::null_mut());

                if OCSP_basic_add1_status(
                    basic,
                    entry.cert_id.as_ptr(),
                    status,
                    reason,
                    revocation_ptr,
                    this_update.as_ptr(),
                    next_update.as_ptr(),
                )
                .is_null()
                {
                    ffi::OCSP_BASICRESP_free(basic);
                    return Err(AppError::Crypto("failed to append OCSP single response".to_string()));
                }
            }

            if OCSP_basic_sign(
                basic,
                signer.cert.as_ptr(),
                signer.key.as_ptr(),
                ffi::EVP_sha256(),
                ptr::null_mut(),
                0,
            )
            != 1
            {
                ffi::OCSP_BASICRESP_free(basic);
                return Err(AppError::Crypto("failed to sign OCSP response".to_string()));
            }

            let response_ptr = ffi::OCSP_response_create(ffi::OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
            if response_ptr.is_null() {
                ffi::OCSP_BASICRESP_free(basic);
                return Err(AppError::Crypto("failed to create OCSP response envelope".to_string()));
            }

            let response = OcspResponse::from_ptr(response_ptr);
            response.to_der().map_err(|e| AppError::Crypto(e.to_string()))
        }
    }
}

fn build_revocation_index(records: Vec<RevocationRecord>) -> HashMap<String, RevocationRecord> {
    records
        .into_iter()
        .map(|record| (normalize_serial(&record.serial), record))
        .collect()
}

fn map_issuer_kind(kind: Option<&IssuerKind>) -> SignerKind {
    match kind {
        Some(IssuerKind::Intermediate) => SignerKind::Intermediate,
        _ => SignerKind::Root,
    }
}

fn choose_signer_kind(entries: &[RequestEntry], has_intermediate: bool) -> Option<SignerKind> {
    let mut decided: Option<SignerKind> = None;
    for entry in entries {
        if let Some(kind) = entry.issuer_hint {
            if let Some(current) = decided {
                if current != kind {
                    return None;
                }
            } else {
                decided = Some(kind);
            }
        }
    }

    if let Some(kind) = decided {
        return Some(kind);
    }

    if has_intermediate {
        Some(SignerKind::Intermediate)
    } else {
        Some(SignerKind::Root)
    }
}

fn map_reason_code(reason: &str) -> c_int {
    let lower = reason.trim().to_ascii_lowercase();
    match lower.as_str() {
        "keycompromise" | "key_compromise" | "key-compromise" => ffi::OCSP_REVOKED_STATUS_KEYCOMPROMISE,
        "cacompromise" | "ca_compromise" | "ca-compromise" => ffi::OCSP_REVOKED_STATUS_CACOMPROMISE,
        "affiliationchanged" | "affiliation_changed" | "affiliation-changed" => {
            ffi::OCSP_REVOKED_STATUS_AFFILIATIONCHANGED
        }
        "superseded" => ffi::OCSP_REVOKED_STATUS_SUPERSEDED,
        "cessationofoperation" | "cessation_of_operation" | "cessation-of-operation" => {
            ffi::OCSP_REVOKED_STATUS_CESSATIONOFOPERATION
        }
        "certificatehold" | "certificate_hold" | "certificate-hold" => {
            ffi::OCSP_REVOKED_STATUS_CERTIFICATEHOLD
        }
        "removefromcrl" | "remove_from_crl" | "remove-from-crl" => ffi::OCSP_REVOKED_STATUS_REMOVEFROMCRL,
        _ => ffi::OCSP_REVOKED_STATUS_UNSPECIFIED,
    }
}

fn normalize_serial(serial: &str) -> String {
    let trimmed = serial.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_ascii_uppercase()
    }
}

fn cert_id_serial_hex(cert_id: *mut ffi::OCSP_CERTID) -> AppResult<String> {
    // SAFETY: OpenSSL fills `serial` with a borrowed ASN1_INTEGER pointer owned by cert_id.
    unsafe {
        let mut serial: *mut ffi::ASN1_INTEGER = ptr::null_mut();
        if OCSP_id_get0_info(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut serial,
            cert_id,
        )
        != 1
        {
            return Err(AppError::Validation("OCSP request is missing certificate serial".to_string()));
        }

        if serial.is_null() {
            return Err(AppError::Validation("OCSP request has null certificate serial".to_string()));
        }

        let asn1_serial = Asn1IntegerRef::from_ptr(serial);
        let serial_hex = asn1_serial
            .to_bn()
            .and_then(|bn| bn.to_hex_str())
            .map(|hex| normalize_serial(&hex.to_string()))
            .map_err(|e| AppError::Crypto(e.to_string()))?;

        Ok(serial_hex)
    }
}

fn parse_request_entries(request: &OcspRequest) -> AppResult<Vec<ParsedRequestEntry>> {
    let mut parsed = Vec::new();

    // SAFETY: We only duplicate CertID objects from request-owned pointers and keep owned copies.
    unsafe {
        let count = OCSP_request_onereq_count(request.as_ptr());
        if count <= 0 {
            return Ok(parsed);
        }

        for index in 0..count {
            let one_req = OCSP_request_onereq_get0(request.as_ptr(), index);
            if one_req.is_null() {
                continue;
            }

            let cert_id_ptr = OCSP_onereq_get0_id(one_req);
            if cert_id_ptr.is_null() {
                continue;
            }

            let serial = cert_id_serial_hex(cert_id_ptr)?;
            let cert_id_dup = OCSP_CERTID_dup(cert_id_ptr);
            if cert_id_dup.is_null() {
                return Err(AppError::Crypto("failed to duplicate OCSP CertID".to_string()));
            }

            parsed.push(ParsedRequestEntry {
                cert_id: OcspCertId::from_ptr(cert_id_dup),
                serial,
            });
        }
    }

    Ok(parsed)
}

fn load_private_key(
    key_pem: &str,
    key_encrypted: bool,
    key_passphrase: Option<&str>,
    label: &str,
) -> AppResult<PKey<Private>> {
    if key_encrypted {
        let passphrase = key_passphrase
            .filter(|pass| !pass.is_empty())
            .ok_or_else(|| AppError::Config(format!("passphrase for {label} key is required")))?;
        PKey::private_key_from_pem_passphrase(key_pem.as_bytes(), passphrase.as_bytes())
            .map_err(|e| AppError::Crypto(e.to_string()))
    } else {
        PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| AppError::Crypto(e.to_string()))
    }
}

fn build_status_only_response(status: OcspResponseStatus) -> AppResult<Vec<u8>> {
    OcspResponse::create(status, None)
        .and_then(|response| response.to_der())
        .map_err(|e| AppError::Crypto(e.to_string()))
}

#[derive(Serialize)]
struct OcspErrorBody {
    error: String,
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "digitca-ocsp",
    })
}

async fn ocsp_post(State(state): State<Arc<OcspResponder>>, body: Bytes) -> Response {
    let der = state.respond_der(&body).await;
    ocsp_der_response(der)
}

async fn ocsp_get(
    State(state): State<Arc<OcspResponder>>,
    Path(request_b64): Path<String>,
) -> Response {
    let request_der = decode_ocsp_request_from_path(&request_b64);
    match request_der {
        Ok(der) => ocsp_der_response(state.respond_der(&der).await),
        Err(err) => {
            let body = Json(OcspErrorBody {
                error: format!("invalid OCSP base64 payload: {err}"),
            });
            (StatusCode::BAD_REQUEST, body).into_response()
        }
    }
}

fn decode_ocsp_request_from_path(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
}

fn ocsp_der_response(der: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, der).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/ocsp-response"),
    );
    response
}

pub fn router(state: Arc<OcspResponder>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ocsp", post(ocsp_post))
        .route("/ocsp/:request_b64", get(ocsp_get))
        .with_state(state)
}

pub async fn run() -> AppResult<()> {
    dotenv().ok();
    init_tracing();

    let config = OcspConfig::from_env()?;
    let storage: Box<dyn CaRepository + Send + Sync> =
        Box::new(MongoStorage::connect(&config.mongodb_uri, &config.mongodb_db).await?);

    let responder = Arc::new(OcspResponder::new(
        storage,
        config.root_ca_key_passphrase,
        config.intermediate_ca_key_passphrase,
        config.next_update_seconds,
    ));

    let addr = format!("{}:{}", config.bind, config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| AppError::Config(format!("failed to bind OCSP server on {addr}: {e}")))?;

    tracing::info!("OCSP responder is listening on http://{addr}");

    axum::serve(listener, router(responder))
        .await
        .map_err(|e| AppError::Config(e.to_string()))
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .try_init();
}

fn must_get(key: &str) -> AppResult<String> {
    env::var(key).map_err(|_| AppError::Config(format!("environment variable {key} is required")))
}

#[cfg(test)]
mod tests {
    use super::OcspResponder;
    use digitca::{
        ca::CertificateAuthority,
        models::{CertificateProfile, IssueIssuer, IssueRequest},
        storage::{CaRepository, InMemoryStorage},
    };
    use openssl::{
        hash::MessageDigest,
        ocsp::{OcspCertId, OcspCertStatus, OcspRequest, OcspResponse, OcspResponseStatus, OcspRevokedStatus},
        x509::X509,
    };

    fn issue_request(common_name: &str) -> IssueRequest {
        IssueRequest {
            common_name: common_name.to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Root,
            dns_names: vec![common_name.to_string()],
            ip_sans: vec![],
            validity_days: 30,
        }
    }

    fn make_ocsp_request(cert_pem: &str, issuer_pem: &str) -> (Vec<u8>, OcspCertId) {
        let cert = X509::from_pem(cert_pem.as_bytes()).expect("leaf cert must parse");
        let issuer = X509::from_pem(issuer_pem.as_bytes()).expect("issuer cert must parse");

        let cert_id =
            OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer).expect("cert id must be created");

        let mut request = OcspRequest::new().expect("request must be created");
        request
            .add_id(
                OcspCertId::from_cert(MessageDigest::sha1(), &cert, &issuer)
                    .expect("cert id for request must be created"),
            )
            .expect("id must be added to request");

        (request.to_der().expect("request der must be created"), cert_id)
    }

    #[tokio::test]
    async fn returns_good_for_active_certificate() {
        let storage = InMemoryStorage::default();
        let root = CertificateAuthority::create_root("DigitCA Root", 365, Some("root-secret"))
            .expect("root must be created");
        storage.upsert_root(&root).await.expect("root must be stored");

        let cert = CertificateAuthority::issue_from_root(&root, issue_request("active.internal"), Some("root-secret"))
            .expect("leaf must be issued");
        storage
            .insert_certificate(&cert)
            .await
            .expect("leaf must be stored");

        let responder = OcspResponder::new(
            Box::new(storage),
            Some("root-secret".to_string()),
            Some("root-secret".to_string()),
            3600,
        );

        let (request_der, cert_id) = make_ocsp_request(&cert.cert_pem, &root.cert_pem);
        let response_der = responder.respond_der(&request_der).await;

        let response = OcspResponse::from_der(&response_der).expect("response must parse");
        assert_eq!(response.status(), OcspResponseStatus::SUCCESSFUL);

        let basic = response.basic().expect("basic response must exist");
        let status = basic.find_status(&cert_id).expect("status must exist");
        assert_eq!(status.status, OcspCertStatus::GOOD);
    }

    #[tokio::test]
    async fn returns_revoked_for_revoked_certificate() {
        let storage = InMemoryStorage::default();
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None).expect("root must be created");
        storage.upsert_root(&root).await.expect("root must be stored");

        let cert =
            CertificateAuthority::issue_from_root(&root, issue_request("revoked.internal"), None).expect("issue cert");
        storage
            .insert_certificate(&cert)
            .await
            .expect("leaf must be stored");
        storage
            .revoke_certificate(&cert.serial, "keyCompromise")
            .await
            .expect("leaf must be revoked");

        let responder = OcspResponder::new(Box::new(storage), None, None, 3600);
        let (request_der, cert_id) = make_ocsp_request(&cert.cert_pem, &root.cert_pem);
        let response_der = responder.respond_der(&request_der).await;

        let response = OcspResponse::from_der(&response_der).expect("response must parse");
        assert_eq!(response.status(), OcspResponseStatus::SUCCESSFUL);

        let basic = response.basic().expect("basic response must exist");
        let status = basic.find_status(&cert_id).expect("status must exist");
        assert_eq!(status.status, OcspCertStatus::REVOKED);
        assert_eq!(status.reason, OcspRevokedStatus::KEY_COMPROMISE);
    }

    #[tokio::test]
    async fn returns_unknown_for_nonexistent_certificate() {
        let storage = InMemoryStorage::default();
        let root = CertificateAuthority::create_root("DigitCA Root", 365, None).expect("root must be created");
        storage.upsert_root(&root).await.expect("root must be stored");

        let cert =
            CertificateAuthority::issue_from_root(&root, issue_request("missing.internal"), None).expect("issue cert");
        let responder = OcspResponder::new(Box::new(storage), None, None, 3600);

        let (request_der, cert_id) = make_ocsp_request(&cert.cert_pem, &root.cert_pem);
        let response_der = responder.respond_der(&request_der).await;

        let response = OcspResponse::from_der(&response_der).expect("response must parse");
        assert_eq!(response.status(), OcspResponseStatus::SUCCESSFUL);

        let basic = response.basic().expect("basic response must exist");
        let status = basic.find_status(&cert_id).expect("status must exist");
        assert_eq!(status.status, OcspCertStatus::UNKNOWN);
    }

    #[tokio::test]
    async fn malformed_request_returns_malformed_response_status() {
        let responder = OcspResponder::new(Box::new(InMemoryStorage::default()), None, None, 3600);
        let response_der = responder.respond_der(b"not-der").await;

        let response = OcspResponse::from_der(&response_der).expect("response must parse");
        assert_eq!(response.status(), OcspResponseStatus::MALFORMED_REQUEST);
    }
}


use async_trait::async_trait;
use digitca::{
    execute_command, Commands,
    error::{AppError, AppResult},
    ldap_auth::Authorizer,
    models::{CertificateProfile, IssueIssuer},
    service::CaService,
    storage::InMemoryStorage,
};

struct AllowAuthorizer;
struct DenyAuthorizer;

#[async_trait]
impl Authorizer for AllowAuthorizer {
    async fn authorize(&self, _username: &str, _password: &str) -> AppResult<()> {
        Ok(())
    }
}

#[async_trait]
impl Authorizer for DenyAuthorizer {
    async fn authorize(&self, _username: &str, _password: &str) -> AppResult<()> {
        Err(AppError::AccessDenied)
    }
}

#[tokio::test]
async fn cli_command_flow_works_with_in_memory_storage() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(
        storage,
        Some("test-passphrase".to_string()),
        Some("intermediate-passphrase".to_string()),
    );
    let auth = AllowAuthorizer;

    let init_output = execute_command(
        Commands::InitRoot {
            common_name: "DigitCA Test Root".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");
    assert!(init_output.contains("Root CA ініціалізовано"));

    let intermediate_output = execute_command(
        Commands::InitIntermediate {
            common_name: "DigitCA Intermediate".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("intermediate init must succeed");
    assert!(intermediate_output.contains("Intermediate CA ініціалізовано"));

    let issue_output = execute_command(
        Commands::Issue {
            common_name: "service.internal".to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Auto,
            dns_names: vec!["service.internal".to_string(), "api.internal".to_string()],
            ip_sans: vec![],
            validity_days: 90,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("issue must succeed");
    assert!(issue_output.contains("Видано сертифікат"));
    assert!(issue_output.contains("ServerTls"));
    assert!(issue_output.contains("Intermediate"));

    let serial = issue_output
        .lines()
        .find_map(|line| line.strip_prefix("Видано сертифікат. Serial: "))
        .expect("serial must be present")
        .split(" | ")
        .next()
        .expect("serial prefix must be present")
        .trim()
        .to_string();

    let verify_before = execute_command(
        Commands::Verify {
            serial: serial.clone(),
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("verify before revoke must succeed");
    assert!(verify_before.contains("Signature valid: true"));
    assert!(verify_before.contains("Revoked: false"));

    let get_output = execute_command(
        Commands::Get {
            serial: serial.clone(),
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("get must succeed");
    assert!(get_output.contains("CN: service.internal"));
    assert!(get_output.contains("Profile: ServerTls"));
    assert!(get_output.contains("Issuer: Some(Intermediate)"));
    assert!(get_output.contains("BEGIN CERTIFICATE"));

    let revoke_output = execute_command(
        Commands::Revoke {
            serial: serial.clone(),
            reason: "keyCompromise".to_string(),
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("revoke must succeed");
    assert!(revoke_output.contains("відкликано"));

    let verify_after = execute_command(
        Commands::Verify {
            serial: serial.clone(),
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("verify after revoke must succeed");
    assert!(verify_after.contains("Revoked: true"));

    let list_output = execute_command(
        Commands::List {
            include_revoked: true,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("list must succeed");
    assert!(list_output.contains(&serial));
    assert!(list_output.contains("ServerTls"));
    assert!(list_output.contains("Some(Intermediate)"));
    assert!(list_output.contains("Revoked"));

    let export_root = execute_command(
        Commands::ExportRoot {
            output: None,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("export root must succeed");
    assert!(export_root.contains("BEGIN CERTIFICATE"));

    let export_intermediate = execute_command(
        Commands::ExportIntermediate {
            output: None,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("export intermediate must succeed");
    assert!(export_intermediate.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn cli_returns_access_denied_when_authorization_fails() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(storage, None, None);
    let auth = DenyAuthorizer;

    let result = execute_command(
        Commands::List {
            include_revoked: false,
            username: "blocked".to_string(),
            password: "wrong".to_string(),
        },
        &auth,
        &service,
    )
    .await;

    assert!(matches!(result, Err(AppError::AccessDenied)));
}

#[tokio::test]
async fn client_auth_profile_can_be_issued_without_dns_names() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(
        storage,
        Some("test-passphrase".to_string()),
        Some("intermediate-passphrase".to_string()),
    );
    let auth = AllowAuthorizer;

    execute_command(
        Commands::InitRoot {
            common_name: "DigitCA Test Root".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");

    let output = execute_command(
        Commands::Issue {
            common_name: "workstation-007".to_string(),
            profile: CertificateProfile::ClientAuth,
            issuer: IssueIssuer::Root,
            dns_names: vec![],
            ip_sans: vec![],
            validity_days: 90,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("client auth issue must succeed without DNS SAN");

    assert!(output.contains("ClientAuth"));
}

#[tokio::test]
async fn server_tls_profile_rejects_missing_dns_names() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(
        storage,
        Some("test-passphrase".to_string()),
        Some("intermediate-passphrase".to_string()),
    );
    let auth = AllowAuthorizer;

    execute_command(
        Commands::InitRoot {
            common_name: "DigitCA Test Root".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");

    let result = execute_command(
        Commands::Issue {
            common_name: "service.internal".to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Root,
            dns_names: vec![],
            ip_sans: vec![],
            validity_days: 90,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await;

    assert!(matches!(result, Err(AppError::Validation(_))));
}

#[tokio::test]
async fn auto_issuer_falls_back_to_root_when_intermediate_missing() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(storage, Some("test-passphrase".to_string()), None);
    let auth = AllowAuthorizer;

    execute_command(
        Commands::InitRoot {
            common_name: "DigitCA Test Root".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");

    let output = execute_command(
        Commands::Issue {
            common_name: "legacy.internal".to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Auto,
            dns_names: vec!["legacy.internal".to_string()],
            ip_sans: vec![],
            validity_days: 90,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("auto issuer must fall back to root");

    assert!(output.contains("Issuer: Root"));
}

#[tokio::test]
async fn audit_log_records_all_operations() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(
        storage,
        Some("test-passphrase".to_string()),
        Some("intermediate-passphrase".to_string()),
    );
    let auth = AllowAuthorizer;

    execute_command(
        Commands::InitRoot {
            common_name: "Audit Test Root".to_string(),
            validity_days: 365,
            username: "alice".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");

    execute_command(
        Commands::Issue {
            common_name: "audit.internal".to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Root,
            dns_names: vec!["audit.internal".to_string()],
            ip_sans: vec![],
            validity_days: 90,
            username: "alice".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("issue must succeed");

    let audit_output = execute_command(
        Commands::AuditLog {
            limit: 50,
            username: "alice".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("audit log must succeed");

    assert!(audit_output.contains("InitRoot"));
    assert!(audit_output.contains("IssueCertificate"));
    assert!(audit_output.contains("actor=alice"));
}

#[tokio::test]
async fn revoke_rejects_invalid_reason() {
    let storage = InMemoryStorage::default();
    let service = CaService::new(storage, Some("test-passphrase".to_string()), None);
    let auth = AllowAuthorizer;

    execute_command(
        Commands::InitRoot {
            common_name: "DigitCA Test Root".to_string(),
            validity_days: 365,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("root init must succeed");

    let issue_output = execute_command(
        Commands::Issue {
            common_name: "service.invalid-reason".to_string(),
            profile: CertificateProfile::ServerTls,
            issuer: IssueIssuer::Root,
            dns_names: vec!["service.invalid-reason".to_string()],
            ip_sans: vec![],
            validity_days: 90,
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await
    .expect("issue must succeed");

    let serial = issue_output
        .lines()
        .find_map(|line| line.strip_prefix("Видано сертифікат. Serial: "))
        .expect("serial must be present")
        .split(" | ")
        .next()
        .expect("serial prefix must be present")
        .trim()
        .to_string();

    let result = execute_command(
        Commands::Revoke {
            serial,
            reason: "totallyUnknownReason".to_string(),
            username: "admin".to_string(),
            password: "secret".to_string(),
        },
        &auth,
        &service,
    )
    .await;

    assert!(matches!(result, Err(AppError::Validation(_))));
}


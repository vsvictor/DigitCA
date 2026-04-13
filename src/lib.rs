pub mod api;
pub mod ca;
pub mod config;
pub mod error;
pub mod ldap_auth;
pub mod ldap_publish;
pub mod models;
pub mod service;
pub mod storage;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::{
    api::{AppState, router},
    config::AppConfig,
    error::{AppError, AppResult},
    ldap_auth::{Authorizer, LdapAuthorizer},
    ldap_publish::LdapPublisher,
    models::{CertificateProfile, IssueIssuer, IssueRequest},
    service::CaService,
    storage::{CaRepository, MongoStorage},
};

#[derive(Debug, Clone, Parser)]
#[command(name = "digitca", about = "LDAP + MongoDB backed Rust Certificate Authority")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Запустити REST API сервер
    Serve {
        #[arg(long, env = "HTTP_BIND", default_value = "0.0.0.0")]
        bind: String,
        #[arg(long, env = "HTTP_PORT", default_value_t = 8080)]
        port: u16,
    },
    InitRoot {
        #[arg(long)]
        common_name: String,
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    InitIntermediate {
        #[arg(long)]
        common_name: String,
        #[arg(long, default_value_t = 1825)]
        validity_days: u32,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Issue {
        #[arg(long)]
        common_name: String,
        #[arg(long, value_enum, default_value_t = CertificateProfile::ServerTls)]
        profile: CertificateProfile,
        #[arg(long, value_enum, default_value_t = IssueIssuer::Auto)]
        issuer: IssueIssuer,
        #[arg(long = "dns")]
        dns_names: Vec<String>,
        #[arg(long = "ip")]
        ip_sans: Vec<String>,
        #[arg(long, default_value_t = 365)]
        validity_days: u32,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Revoke {
        #[arg(long)]
        serial: String,
        #[arg(long, default_value = "unspecified")]
        reason: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Get {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    List {
        #[arg(long, default_value_t = false)]
        include_revoked: bool,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Verify {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    ExportRoot {
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    ExportIntermediate {
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    AuditLog {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
}

pub async fn run() -> AppResult<()> {
    dotenv().ok();
    init_tracing();

    let cli = Cli::parse();
    let config = AppConfig::from_env()?;

    let storage: Box<dyn CaRepository + Send + Sync> =
        Box::new(MongoStorage::connect(&config.mongodb_uri, &config.mongodb_db).await?);
    let service = CaService::new(
        storage,
        config.root_ca_key_passphrase.clone(),
        config.intermediate_ca_key_passphrase.clone(),
    );
    let ldap: Arc<dyn Authorizer + Send + Sync> =
        Arc::new(LdapAuthorizer::new(config.ldap.clone()));

    // Команда serve запускає REST API
    if let Commands::Serve { bind, port } = &cli.command {
        let publisher = LdapPublisher::new(config.ldap.clone(), config.ldap_publish_enabled);
        let state = AppState {
            service: Arc::new(service),
            ldap,
            publisher,
            enforce_https_basic_auth: config.basic_auth_require_https,
        };
        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| AppError::Config(format!("не вдалося прослуховувати {addr}: {e}")))?;
        tracing::info!("REST API доступний на http://{addr}");
        axum::serve(listener, router(state, &config.cors_allowed_origins))
            .await
            .map_err(|e| AppError::Config(e.to_string()))?;
        return Ok(());
    }

    // CLI-команди
    let output = execute_command(cli.command, ldap.as_ref(), &service).await?;
    if !output.is_empty() {
        println!("{output}");
    }

    Ok(())
}

pub async fn execute_command<A, R>(
    command: Commands,
    authorizer: &A,
    service: &CaService<R>,
) -> AppResult<String>
where
    A: Authorizer + ?Sized,
    R: CaRepository,
{
    match command {
        Commands::Serve { .. } => Ok(String::new()), // handled above

        Commands::InitRoot { common_name, validity_days, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let serial = service.init_root(&common_name, validity_days, &username).await?;
            Ok(format!("Root CA ініціалізовано. Serial: {serial}"))
        }
        Commands::InitIntermediate { common_name, validity_days, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let serial = service.init_intermediate(&common_name, validity_days, &username).await?;
            Ok(format!("Intermediate CA ініціалізовано. Serial: {serial}"))
        }
        Commands::Issue { common_name, profile, issuer, dns_names, ip_sans, validity_days, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let cert = service
                .issue(IssueRequest { common_name, profile, issuer, dns_names, ip_sans, validity_days }, &username)
                .await?;
            Ok(format!(
                "Видано сертифікат. Serial: {} | Profile: {:?} | Issuer: {:?}",
                cert.serial,
                cert.profile,
                cert.issuer_kind.clone().unwrap_or(crate::models::IssuerKind::Root)
            ))
        }
        Commands::Revoke { serial, reason, username, password } => {
            authorizer.authorize(&username, &password).await?;
            service.revoke(&serial, &reason, &username).await?;
            Ok(format!("Сертифікат {serial} відкликано"))
        }
        Commands::Get { serial, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let cert = service.get(&serial, &username).await?;
            Ok(format!(
                "Serial: {}\nCN: {}\nProfile: {:?}\nIssuer: {:?}\nIssuer Serial: {:?}\nDNS: {:?}\nStatus: {:?}\nNot After: {}\n\n{}",
                cert.serial, cert.common_name, cert.profile, cert.issuer_kind,
                cert.issuer_serial, cert.dns_names, cert.status, cert.not_after, cert.cert_pem
            ))
        }
        Commands::List { include_revoked, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let certs = service.list(include_revoked, &username).await?;
            Ok(certs
                .into_iter()
                .map(|cert| format!(
                    "{} | {} | {:?} | {:?} | {:?} | {}",
                    cert.serial, cert.common_name, cert.profile, cert.issuer_kind, cert.status, cert.not_after
                ))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        Commands::Verify { serial, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let result = service.verify(&serial, &username).await?;
            Ok(format!(
                "Serial: {}\nSignature valid: {}\nRevoked: {}\nTime valid: {}",
                result.serial, result.signature_valid, result.revoked, result.time_valid
            ))
        }
        Commands::ExportRoot { output, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let pem = service.root_pem(&username).await?;
            match output {
                Some(path) => {
                    std::fs::write(&path, pem).map_err(|e| AppError::Storage(e.to_string()))?;
                    Ok(format!("Root CA збережено у {path}"))
                }
                None => Ok(pem),
            }
        }
        Commands::ExportIntermediate { output, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let pem = service.intermediate_pem(&username).await?;
            match output {
                Some(path) => {
                    std::fs::write(&path, pem).map_err(|e| AppError::Storage(e.to_string()))?;
                    Ok(format!("Intermediate CA збережено у {path}"))
                }
                None => Ok(pem),
            }
        }
        Commands::AuditLog { limit, username, password } => {
            authorizer.authorize(&username, &password).await?;
            let events = service.audit_log(limit).await?;
            if events.is_empty() {
                return Ok("Журнал аудиту порожній".to_string());
            }
            Ok(events
                .into_iter()
                .map(|e| format!(
                    "{} | {:?} | actor={} | target={} | {}",
                    e.occurred_at.format("%Y-%m-%d %H:%M:%S"),
                    e.kind,
                    e.actor,
                    e.target_serial.as_deref().unwrap_or("-"),
                    e.details
                ))
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .try_init();
}



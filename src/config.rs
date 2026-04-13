use std::env;

use crate::error::{AppError, AppResult};

#[derive(Clone, Debug)]
pub struct AppConfig {
	pub mongodb_uri: String,
	pub mongodb_db: String,
	pub ldap: LdapConfig,
	pub root_ca_key_passphrase: Option<String>,
	pub intermediate_ca_key_passphrase: Option<String>,
	pub http_bind: String,
	pub http_port: u16,
	pub ldap_publish_enabled: bool,
	pub basic_auth_require_https: bool,
	pub cors_allowed_origins: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct LdapConfig {
	pub url: String,
	pub bind_dn: String,
	pub bind_password: String,
	pub base_dn: String,
	pub user_attr: String,
	pub required_group: Option<String>,
}

impl AppConfig {
	pub fn from_env() -> AppResult<Self> {
		Ok(Self {
			mongodb_uri: must_get("MONGODB_URI")?,
			mongodb_db: must_get("MONGODB_DB")?,
			root_ca_key_passphrase: env::var("ROOT_CA_KEY_PASSPHRASE").ok(),
			intermediate_ca_key_passphrase: env::var("INTERMEDIATE_CA_KEY_PASSPHRASE")
				.ok()
				.or_else(|| env::var("ROOT_CA_KEY_PASSPHRASE").ok()),
			http_bind: env::var("HTTP_BIND").unwrap_or_else(|_| "0.0.0.0".to_string()),
			http_port: env::var("HTTP_PORT")
				.ok()
				.and_then(|v| v.parse().ok())
				.unwrap_or(8080),
			ldap_publish_enabled: env::var("LDAP_PUBLISH_ENABLED")
				.map(|v| v == "true" || v == "1")
				.unwrap_or(false),
			basic_auth_require_https: parse_bool_env("BASIC_AUTH_REQUIRE_HTTPS", true),
			cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
				.ok()
				.map(|v| {
					v.split(',')
						.map(|s| s.trim().to_string())
						.filter(|s| !s.is_empty())
						.collect()
				})
				.unwrap_or_default(),
			ldap: LdapConfig {
				url: must_get("LDAP_URL")?,
				bind_dn: must_get("LDAP_BIND_DN")?,
				bind_password: must_get("LDAP_BIND_PASSWORD")?,
				base_dn: must_get("LDAP_BASE_DN")?,
				user_attr: env::var("LDAP_USER_ATTR").unwrap_or_else(|_| "uid".to_string()),
				required_group: env::var("LDAP_REQUIRED_GROUP").ok(),
			},
		})
	}
}

fn parse_bool_env(key: &str, default: bool) -> bool {
	env::var(key)
		.map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
		.unwrap_or(default)
}

fn must_get(key: &str) -> AppResult<String> {
	env::var(key).map_err(|_| AppError::Config(format!("змінна {key} не визначена")))
}


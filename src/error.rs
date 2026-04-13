use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
	#[error("конфігурація неповна: {0}")]
	Config(String),

	#[error("LDAP помилка: {0}")]
	Ldap(String),

	#[error("доступ заборонено")]
	AccessDenied,

	#[error("MongoDB помилка: {0}")]
	Storage(String),

	#[error("сертифікат не знайдено: {0}")]
	NotFound(String),

	#[error("помилка валідації: {0}")]
	Validation(String),

	#[error("криптографічна помилка: {0}")]
	Crypto(String),

	#[error("ще не реалізовано: {0}")]
	NotImplemented(String),
}

pub type AppResult<T> = Result<T, AppError>;


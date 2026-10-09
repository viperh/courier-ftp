//! Outgoing mail over SMTP (recovery codes; T89 adds invite mail). Optional:
//! without `SMTP_HOST` nothing is sent and the operator hands codes out (T86
//! `admin user recovery-code`).

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::SmtpConfig;

/// Subject of the recovery-code mail.
pub const RECOVERY_SUBJECT: &str = "Your courier-ftp recovery code";

/// Mail errors (never contain the message body).
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// Bad `From`/`To` address.
    #[error("invalid address: {0}")]
    Address(#[from] lettre::address::AddressError),
    /// Message construction failed.
    #[error("cannot build message: {0}")]
    Build(#[from] lettre::error::Error),
    /// SMTP failure.
    #[error("SMTP error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
}

fn transport(cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, MailError> {
    let builder = if cfg.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?
    };
    let builder = builder
        .port(cfg.port)
        .timeout(Some(std::time::Duration::from_secs(30)));
    let builder = match (&cfg.user, &cfg.password) {
        (Some(user), Some(pass)) => {
            builder.credentials(Credentials::new(user.clone(), pass.0.clone()))
        }
        _ => builder,
    };
    Ok(builder.build())
}

/// Sends a plain-text mail.
///
/// # Errors
/// [`MailError`].
pub async fn send(cfg: &SmtpConfig, to: &str, subject: &str, body: String) -> Result<(), MailError> {
    let msg = Message::builder()
        .from(cfg.from.parse::<Mailbox>()?)
        .to(to.parse::<Mailbox>()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;
    transport(cfg)?.send(msg).await?;
    Ok(())
}

/// The recovery-code mail body.
#[must_use]
pub fn recovery_body(code: &str, public_url: &str) -> String {
    format!(
        "A recovery of your courier-ftp sync account on {public_url} was requested.\n\n\
         Recovery code: {code}\n\n\
         Enter it in courier-ftp together with your 24-word recovery key. The code expires \
         in 24 hours. If you did not ask for this, ignore this mail.\n"
    )
}

//! Outgoing mail over SMTP. Optional: without `SMTP_*` recovery codes are
//! issued with the admin CLI and invites are copy-paste tokens.

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::SmtpConfig;

/// Mail errors.
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
    let builder = builder.port(cfg.port);
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
pub async fn send(
    cfg: &SmtpConfig,
    to: &str,
    subject: &str,
    body: String,
) -> Result<(), MailError> {
    let msg = Message::builder()
        .from(cfg.from.parse::<Mailbox>()?)
        .to(to.parse::<Mailbox>()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;
    transport(cfg)?.send(msg).await?;
    Ok(())
}

/// The body of an instance invite mail (`admin invite --email`).
#[must_use]
pub fn invite_body(link: &str) -> String {
    format!(
        "You have been invited to a courier-ftp sync server.\n\n\
         Paste this invite token into courier-ftp when you set up sync:\n\n{link}\n\n\
         The invite can be used once and expires in 7 days.\n"
    )
}

/// The body of a recovery-code mail.
#[must_use]
pub fn recovery_body(code: &str) -> String {
    format!(
        "A recovery of your courier-ftp sync account was requested.\n\n\
         Recovery code: {code}\n\n\
         Enter it in courier-ftp together with your 24-word recovery key. The code \
         expires in 24 hours. If you did not ask for this, ignore this mail.\n"
    )
}

/// Subject of recovery-code mails.
pub const RECOVERY_SUBJECT: &str = "Your courier-ftp recovery code";
/// Subject of invite mails.
pub const INVITE_SUBJECT: &str = "Your courier-ftp sync invite";

/// One mail a [`Mailer::Recording`] kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    /// Recipient.
    pub to: String,
    /// Subject.
    pub subject: String,
    /// Body.
    pub body: String,
}

/// Where mail goes: SMTP, nowhere (no SMTP configured: recovery codes come
/// from the admin CLI, invites are copy-paste tokens), or a recording fake
/// (tests).
#[derive(Debug, Clone, Default)]
pub enum Mailer {
    /// No SMTP: nothing is sent.
    #[default]
    Disabled,
    /// The configured relay.
    Smtp(SmtpConfig),
    /// Keeps the mails (tests).
    Recording(std::sync::Arc<std::sync::Mutex<Vec<SentMail>>>),
}

impl Mailer {
    /// SMTP when configured, else disabled.
    #[must_use]
    pub fn from_config(smtp: Option<&SmtpConfig>) -> Self {
        smtp.map_or(Self::Disabled, |c| Self::Smtp(c.clone()))
    }

    /// Whether mail can be sent.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Sends a plain-text mail.
    ///
    /// # Errors
    /// [`MailError`]; a disabled mailer does nothing.
    pub async fn send(&self, to: &str, subject: &str, body: String) -> Result<(), MailError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Smtp(cfg) => send(cfg, to, subject, body).await,
            Self::Recording(sent) => {
                if let Ok(mut s) = sent.lock() {
                    s.push(SentMail {
                        to: to.to_owned(),
                        subject: subject.to_owned(),
                        body,
                    });
                }
                Ok(())
            }
        }
    }
}

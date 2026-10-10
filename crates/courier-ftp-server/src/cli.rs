//! Command line of the `courier-ftp-server` binary (T86).
//!
//! ```text
//! courier-ftp-server [--config FILE] serve [--migrate]
//! courier-ftp-server [--config FILE] migrate
//! courier-ftp-server [--config FILE] admin user list
//! courier-ftp-server [--config FILE] admin user create|disable|recovery-code <EMAIL>
//! courier-ftp-server [--config FILE] admin invite <EMAIL> [--no-email]
//! courier-ftp-server [--config FILE] admin registration open|invite-only|closed
//! courier-ftp-server [--config FILE] admin gc
//! courier-ftp-server healthcheck [--addr HOST:PORT]
//! courier-ftp-server --help | --version
//! ```
//!
//! Hand-written instead of clap: only the client binary may use clap
//! (`scripts/check-layering.py`), and the grammar is small.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::admin::{self, AdminError};
use crate::config::{Config, DEFAULT_BIND};
use crate::registration::{self, RegistrationMode};
use crate::{db, healthcheck, logging, mail, serve};

/// The usage text (`--help`).
pub const USAGE: &str = "\
courier-ftp-server: self-hosted, end-to-end encrypted sync server for courier-ftp

USAGE:
    courier-ftp-server [--config FILE] <COMMAND>

COMMANDS:
    serve [--migrate]                         Run the server (--migrate: apply pending migrations)
    migrate                                   Apply pending database migrations and exit
    admin user list                           List accounts
    admin user create <EMAIL>                 Create a registration invite for EMAIL
    admin user disable <EMAIL>                Disable an account and revoke its tokens
    admin user recovery-code <EMAIL>          Issue a one-time recovery code (24 h)
    admin invite <EMAIL> [--no-email]         Create a registration invite (mailed if SMTP is set)
    admin registration open|invite-only|closed
                                              Set who may register
    admin gc                                  Purge expired tokens, invites and old tombstones
    healthcheck [--addr HOST:PORT]            Probe the local /healthz (container HEALTHCHECK)

OPTIONS:
    --config FILE   TOML config (default: $COURIER_SERVER_CONFIG, else ./courier-ftp-server.toml
                    if present); environment variables override it
    -h, --help      Print this help
    -V, --version   Print the version

Configuration: see docs/self-hosting.md (DATABASE_URL, COURIER_SERVER_SECRET,
COURIER_PUBLIC_URL, ...).
";

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// `--config FILE`.
    pub config: Option<PathBuf>,
    /// The command.
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the HTTP server.
    Serve {
        /// Apply pending migrations instead of refusing to start.
        migrate: bool,
    },
    /// Apply pending migrations and exit.
    Migrate,
    /// An admin command.
    Admin(AdminCommand),
    /// Probe `/healthz`.
    Healthcheck {
        /// Address to probe (default: from `COURIER_BIND`).
        addr: Option<SocketAddr>,
    },
    /// Print the usage.
    Help,
    /// Print the version.
    Version,
}

/// `admin …`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    /// `user list`.
    UserList,
    /// `user create <email>` (an invite: passwords are set client-side).
    UserCreate(String),
    /// `user disable <email>`.
    UserDisable(String),
    /// `user recovery-code <email>`.
    UserRecoveryCode(String),
    /// `invite <email> [--no-email]`.
    Invite {
        /// The invitee.
        email: String,
        /// Don't mail it even if SMTP is configured.
        no_email: bool,
    },
    /// `registration <mode>`.
    Registration(RegistrationMode),
    /// `gc`.
    Gc,
}

/// A command-line error (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}\n\nRun `courier-ftp-server --help` for usage.")]
pub struct UsageError(pub String);

fn usage(msg: impl Into<String>) -> UsageError {
    UsageError(msg.into())
}

impl Cli {
    /// Parses the arguments after the program name.
    ///
    /// # Errors
    /// [`UsageError`] for anything that is not in the grammar.
    pub fn parse<I, S>(args: I) -> Result<Self, UsageError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut config = None;
        let mut rest = Vec::new();
        let mut it = args.into_iter().map(Into::into);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--config" => {
                    let v = it.next().ok_or_else(|| usage("--config needs a FILE"))?;
                    config = Some(PathBuf::from(v));
                }
                s if s.starts_with("--config=") => {
                    config = Some(PathBuf::from(&s["--config=".len()..]));
                }
                "-h" | "--help" | "help" => {
                    return Ok(Self {
                        config,
                        command: Command::Help,
                    });
                }
                "-V" | "--version" => {
                    return Ok(Self {
                        config,
                        command: Command::Version,
                    });
                }
                _ => rest.push(a),
            }
        }
        let words: Vec<&str> = rest.iter().map(String::as_str).collect();
        let command = match words.as_slice() {
            [] => return Err(usage("missing command")),
            ["serve"] => Command::Serve { migrate: false },
            ["serve", "--migrate"] => Command::Serve { migrate: true },
            ["migrate"] => Command::Migrate,
            ["healthcheck"] => Command::Healthcheck { addr: None },
            ["healthcheck", "--addr", a] => Command::Healthcheck {
                addr: Some(
                    a.parse()
                        .map_err(|e| usage(format!("invalid --addr `{a}`: {e}")))?,
                ),
            },
            ["admin", tail @ ..] => Command::Admin(parse_admin(tail)?),
            [other, ..] => return Err(usage(format!("unknown command or argument `{other}`"))),
        };
        Ok(Self { config, command })
    }
}

fn parse_admin(words: &[&str]) -> Result<AdminCommand, UsageError> {
    Ok(match words {
        ["user", "list"] => AdminCommand::UserList,
        ["user", "create", email] => AdminCommand::UserCreate((*email).to_owned()),
        ["user", "disable", email] => AdminCommand::UserDisable((*email).to_owned()),
        ["user", "recovery-code", email] => AdminCommand::UserRecoveryCode((*email).to_owned()),
        ["invite", email] => AdminCommand::Invite {
            email: (*email).to_owned(),
            no_email: false,
        },
        ["invite", "--no-email", email] | ["invite", email, "--no-email"] => AdminCommand::Invite {
            email: (*email).to_owned(),
            no_email: true,
        },
        ["registration", mode] => AdminCommand::Registration(mode.parse().map_err(usage)?),
        ["gc"] => AdminCommand::Gc,
        _ => {
            return Err(usage(format!(
                "unknown admin command `{}`",
                words.join(" ")
            )));
        }
    })
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("courier-ftp-server: {msg}");
    ExitCode::FAILURE
}

/// Parses `std::env::args` and runs the command.
pub async fn main() -> ExitCode {
    match Cli::parse(std::env::args().skip(1)) {
        Ok(cli) => run(cli).await,
        Err(e) => {
            eprintln!("courier-ftp-server: {e}");
            ExitCode::from(2)
        }
    }
}

/// Runs a parsed command line.
pub async fn run(cli: Cli) -> ExitCode {
    match &cli.command {
        Command::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!("courier-ftp-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Healthcheck { addr } => return run_healthcheck(*addr).await,
        _ => {}
    }
    let config = match Config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    match cli.command {
        Command::Serve { migrate } => {
            logging::init(config.log_format);
            match serve::run(config, migrate).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %e, "refusing to start");
                    fail(e)
                }
            }
        }
        Command::Migrate => {
            logging::init(config.log_format);
            let pool = match config.require_database_url() {
                Ok(url) => db::connect(url).await,
                Err(e) => return fail(e),
            };
            let pool = match pool {
                Ok(p) => p,
                Err(e) => return fail(format!("database error: {e}")),
            };
            match db::migrate(&pool).await {
                Ok(()) => {
                    println!("migrations applied");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("migration failed: {e}")),
            }
        }
        Command::Admin(command) => match run_admin(&config, command).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Healthcheck { .. } | Command::Help | Command::Version => ExitCode::SUCCESS,
    }
}

async fn run_healthcheck(addr: Option<SocketAddr>) -> ExitCode {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let addr = match addr {
        Some(a) => a,
        None => match env("COURIER_BIND")
            .unwrap_or_else(|| DEFAULT_BIND.to_owned())
            .parse()
        {
            Ok(a) => healthcheck::probe_addr(a),
            Err(e) => return fail(format!("invalid COURIER_BIND: {e}")),
        },
    };
    match healthcheck::run(addr, env("COURIER_TLS_CERT").is_some()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

async fn run_admin(config: &Config, command: AdminCommand) -> Result<(), AdminError> {
    let url = config
        .require_database_url()
        .map_err(|e| AdminError::Invalid(e.to_string()))?;
    let pool = db::connect(url).await?;
    match db::migration_status(&pool).await? {
        db::MigrationStatus::Current => {}
        other => {
            return Err(AdminError::Invalid(format!(
                "database schema is not current ({other:?}); run `courier-ftp-server migrate` first"
            )));
        }
    }
    match command {
        AdminCommand::UserCreate(email) => invite(config, &pool, &email, false).await,
        AdminCommand::Invite { email, no_email } => invite(config, &pool, &email, !no_email).await,
        AdminCommand::UserDisable(email) => {
            let out = admin::user::disable(&pool, &email).await?;
            println!("disabled {email}; revoked {} token(s)", out.tokens_revoked);
            Ok(())
        }
        AdminCommand::UserList => {
            let users = admin::user::list(&pool).await?;
            println!(
                "{:<40} {:<22} {:<8} {:<5} {:>7}",
                "EMAIL", "CREATED", "DISABLED", "ADMIN", "DEVICES"
            );
            for u in users {
                println!(
                    "{:<40} {:<22} {:<8} {:<5} {:>7}",
                    u.email,
                    u.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
                    if u.disabled { "yes" } else { "no" },
                    if u.is_instance_admin { "yes" } else { "no" },
                    u.devices
                );
            }
            Ok(())
        }
        AdminCommand::UserRecoveryCode(email) => {
            let code = admin::user::recovery_code(&pool, &email).await?;
            println!("recovery code for {email} (valid 24 hours, single use):");
            println!("  {}", code.as_str());
            let mailer = mail::Mailer::from_config(config.smtp.as_ref());
            if mailer.enabled() {
                match mailer
                    .send(&email, mail::RECOVERY_SUBJECT, mail::recovery_body(&code))
                    .await
                {
                    Ok(()) => println!("  mailed to {email}"),
                    Err(e) => eprintln!("  could not send mail ({e}); hand the code over"),
                }
            }
            Ok(())
        }
        AdminCommand::Registration(mode) => {
            registration::set_mode(&pool, mode).await?;
            println!("registration mode set to {mode}");
            Ok(())
        }
        AdminCommand::Gc => {
            let r = admin::gc::run(&pool, config).await?;
            println!(
                "gc: removed {} expired token(s), {} expired login state(s)/codes, \
                 {} expired invite(s), {} tombstone(s) in {} vault(s)",
                r.expired_tokens,
                r.expired_other,
                r.expired_invites,
                r.purged_tombstones,
                r.gc_floor_vaults
            );
            Ok(())
        }
    }
}

async fn invite(
    config: &Config,
    pool: &sqlx_postgres::PgPool,
    email: &str,
    send_mail: bool,
) -> Result<(), AdminError> {
    let inv = admin::invite::create(pool, email).await?;
    println!(
        "invite for {} (single use, expires {}):",
        inv.email,
        inv.expires_at.format("%Y-%m-%d %H:%M UTC")
    );
    println!("  server:       {}", config.public_url);
    println!("  invite token: {}", inv.token);
    let mailer = mail::Mailer::from_config(config.smtp.as_ref());
    if send_mail && mailer.enabled() {
        let text = format!("server: {}\ninvite token: {}", config.public_url, inv.token);
        match mailer
            .send(&inv.email, mail::INVITE_SUBJECT, mail::invite_body(&text))
            .await
        {
            Ok(()) => println!("  mailed to {}", inv.email),
            Err(e) => eprintln!("  could not send mail ({e}); hand the token over manually"),
        }
    } else {
        println!("  (no mail sent; hand the server URL and token to the user)");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cli, UsageError> {
        Cli::parse(args.iter().copied())
    }

    #[test]
    fn commands() {
        assert_eq!(
            p(&["serve"]).unwrap().command,
            Command::Serve { migrate: false }
        );
        let c = p(&["--config", "/etc/c.toml", "serve", "--migrate"]).unwrap();
        assert_eq!(c.command, Command::Serve { migrate: true });
        assert_eq!(c.config, Some(PathBuf::from("/etc/c.toml")));
        assert_eq!(
            p(&["migrate", "--config=x.toml"]).unwrap().config,
            Some(PathBuf::from("x.toml"))
        );
        assert_eq!(
            p(&["healthcheck", "--addr", "127.0.0.1:9"])
                .unwrap()
                .command,
            Command::Healthcheck {
                addr: Some("127.0.0.1:9".parse().unwrap())
            }
        );
        assert_eq!(p(&["--help"]).unwrap().command, Command::Help);
        assert_eq!(p(&["-V"]).unwrap().command, Command::Version);
    }

    #[test]
    fn admin_commands() {
        let a = |args: &[&str]| match p(args).unwrap().command {
            Command::Admin(c) => c,
            other => panic!("{other:?}"),
        };
        assert_eq!(a(&["admin", "user", "list"]), AdminCommand::UserList);
        assert_eq!(
            a(&["admin", "user", "disable", "a@b.c"]),
            AdminCommand::UserDisable("a@b.c".into())
        );
        assert_eq!(
            a(&["admin", "user", "recovery-code", "a@b.c"]),
            AdminCommand::UserRecoveryCode("a@b.c".into())
        );
        assert_eq!(
            a(&["admin", "invite", "a@b.c", "--no-email"]),
            AdminCommand::Invite {
                email: "a@b.c".into(),
                no_email: true
            }
        );
        assert_eq!(
            a(&["admin", "registration", "invite-only"]),
            AdminCommand::Registration(RegistrationMode::InviteOnly)
        );
        assert_eq!(a(&["admin", "gc"]), AdminCommand::Gc);
    }

    #[test]
    fn errors() {
        for bad in [
            &[][..],
            &["serve", "--now"],
            &["admin"],
            &["admin", "registration", "sometimes"],
            &["admin", "user", "delete", "a@b.c"],
            &["healthcheck", "--addr", "nope"],
            &["--config"],
            &["frobnicate"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        assert!(
            p(&["frobnicate"])
                .unwrap_err()
                .to_string()
                .contains("--help")
        );
    }
}

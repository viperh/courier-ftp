//! Command-line arguments (T70): what to connect to at start, directory and
//! logging overrides, and the `generate` subcommand for packagers.
//!
//! Launch intents (URLs, `--site`, a local directory) are checked here,
//! before the terminal is taken over, and handed to the app as a
//! [`Launch`]; the app connects once the vault is unlocked or skipped.

use std::{io::Write, path::PathBuf};

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use courier_ftp_core::model::{LogonType, RemotePath};

use crate::{
    action::ConnectRequest,
    config::{get_config_dir, get_data_dir},
};

/// URL schemes accepted on the command line.
const SCHEMES: [&str; 4] = ["sftp://", "ftp://", "ftps://", "ftpes://"];

#[derive(Parser, Debug)]
#[command(
    name = "courier-ftp",
    author,
    version = version(),
    about,
    disable_version_flag = true,
    after_help = "\
Examples:
  courier-ftp sftp://alice@example.com/var/www
  courier-ftp --site Work/Production/web01 --local ~/projects/site
  courier-ftp ~/Downloads
  courier-ftp ftp://host-a ftps://host-b      (one tab each)"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Server URLs to connect to at start (sftp://user@host:port/path,
    /// ftp://, ftps://, ftpes://; one tab each), or one local directory to
    /// start the local pane in. Leave the password out of URLs: it is asked
    /// for when connecting
    #[arg(value_name = "URL_OR_PATH")]
    pub(crate) targets: Vec<String>,

    /// Connect to a Site Manager entry by its path ("Work/Production/web01");
    /// repeat for several tabs. Waits for the vault to be unlocked
    #[arg(short, long = "site", value_name = "PATH")]
    pub(crate) sites: Vec<String>,

    /// The local directory to start in (also the local side of the URL or
    /// site connections)
    #[arg(short, long, value_name = "DIR")]
    pub(crate) local: Option<PathBuf>,

    /// How to log in to the URLs given: `ask` asks for the password,
    /// `interactive` answers every server prompt by hand. Ignores a
    /// password in the URL
    #[arg(long, value_enum, value_name = "TYPE")]
    pub(crate) logontype: Option<LogonChoice>,

    /// Use DIR for the settings (instead of COURIER_FTP_CONFIG,
    /// COURIER_FTP_HOME or the system default)
    #[arg(long, value_name = "DIR")]
    pub(crate) config_dir: Option<PathBuf>,

    /// Use DIR for the vault, logs and the queue (instead of
    /// COURIER_FTP_DATA, COURIER_FTP_HOME or the system default)
    #[arg(long, value_name = "DIR")]
    pub(crate) data_dir: Option<PathBuf>,

    /// Skip the vault for this run: quickconnect only, nothing is saved
    /// (no sites, history, bookmarks or trusted host keys)
    #[arg(long, conflicts_with = "sites")]
    pub(crate) no_vault: bool,

    /// Don't unlock the vault with the system keyring this run; ask for the
    /// master password
    #[arg(long, conflicts_with = "no_vault")]
    pub(crate) no_keyring: bool,

    /// Tick rate, i.e. number of ticks per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 4.0)]
    pub(crate) tick_rate: f64,

    /// Frame rate, i.e. number of frames per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 60.0)]
    pub(crate) frame_rate: f64,

    /// Write debug-level application logs (they may contain hostnames,
    /// user names and paths)
    #[arg(long)]
    pub(crate) debug: bool,

    /// Message log debug level for this run: 0 none, 1 warning, 2 info,
    /// 3 verbose (adds raw listings and TLS/SSH details), 4 debug
    #[arg(long, value_name = "0-4", value_parser = clap::value_parser!(u8).range(0..=4))]
    pub(crate) debug_level: Option<u8>,

    /// Also write the message log to FILE this run (the session log, as
    /// with `logging.log_to_file`; it names servers, users and paths)
    #[arg(long, value_name = "FILE")]
    pub(crate) log_file: Option<PathBuf>,

    /// Don't check for new releases this run (also:
    /// COURIER_FTP_NO_UPDATE_CHECK=1, for packagers)
    #[arg(long)]
    pub(crate) no_update_check: bool,

    /// Print the version, the directories and the vault path
    #[arg(short = 'V', long, action = ArgAction::SetTrue)]
    pub(crate) version: bool,
}

/// `--logontype`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogonChoice {
    /// Ask for the password when connecting.
    Ask,
    /// Ask for every prompt the server sends.
    Interactive,
}

/// What to do once the app has started (T70).
#[derive(Debug, Default)]
pub(crate) struct Launch {
    /// Servers to connect to, one tab each, in order.
    pub(crate) urls: Vec<ConnectRequest>,
    /// Site Manager paths to connect to after the URLs, one tab each.
    pub(crate) sites: Vec<String>,
    /// The local pane's start directory (absolute).
    pub(crate) local_dir: Option<RemotePath>,
    /// Some URL carried a password (warned about before the TUI starts).
    pub(crate) password_in_url: bool,
}

impl Launch {
    /// Whether anything connects at start.
    pub(crate) fn connects(&self) -> bool {
        !self.urls.is_empty() || !self.sites.is_empty()
    }
}

/// Shown on stderr when a URL on the command line has a password.
pub(crate) const PASSWORD_WARNING: &str = "warning: a password given in a URL is visible in \
your shell history and to other users in the process list. Leave it out \
(sftp://user@host) to be asked for it.";

impl Cli {
    /// The launch intents, checked: URLs parse, at most one local
    /// directory and it exists, `--logontype` only with URLs. The error is
    /// a message for the user; it never contains a password.
    pub(crate) fn launch(&self) -> Result<Launch, String> {
        let mut launch = Launch {
            sites: self
                .sites
                .iter()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.trim_matches('/').is_empty())
                .collect(),
            ..Launch::default()
        };
        if launch.sites.len() != self.sites.len() {
            return Err("--site needs a site path, like Work/Production/web01".to_owned());
        }
        let mut local: Option<PathBuf> = self.local.clone();
        for target in &self.targets {
            if let Some((scheme, _)) = target.split_once("://") {
                let lower = target.to_ascii_lowercase();
                if !SCHEMES.iter().any(|s| lower.starts_with(s)) {
                    return Err(format!(
                        "unsupported URL scheme `{scheme}://` (use sftp://, ftp://, ftps:// or ftpes://)"
                    ));
                }
                let mut request = crate::ui::request_from_url(target)
                    .map_err(|e| format!("bad URL `{}`: {e}", redact(target)))?;
                if request.info.logon.password().is_some() {
                    launch.password_in_url = true;
                }
                if let Some(choice) = self.logontype {
                    request.info.logon = choice.logon(&request.info.logon);
                }
                launch.urls.push(request);
            } else if local.is_some() {
                return Err(format!(
                    "`{target}`: only one local directory can be given (with --local or as an argument)"
                ));
            } else {
                local = Some(PathBuf::from(target));
            }
        }
        if self.logontype.is_some() && launch.urls.is_empty() {
            return Err("--logontype needs a server URL".to_owned());
        }
        if let Some(dir) = local {
            launch.local_dir = Some(local_dir(&dir)?);
        }
        Ok(launch)
    }
}

impl LogonChoice {
    /// `logon` with this logon type; the password (if any) is dropped.
    /// Anonymous logins stay anonymous.
    fn logon(self, logon: &LogonType) -> LogonType {
        if matches!(logon, LogonType::Anonymous) {
            return logon.clone();
        }
        let user = logon.user().to_owned();
        match self {
            LogonChoice::Ask => LogonType::AskForPassword { user },
            LogonChoice::Interactive => LogonType::Interactive { user },
        }
    }
}

/// `dir` as an absolute local directory the panes can open.
fn local_dir(dir: &std::path::Path) -> Result<RemotePath, String> {
    let shown = dir.display();
    let meta = std::fs::metadata(dir).map_err(|e| format!("local directory `{shown}`: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("`{shown}` is not a directory"));
    }
    let absolute = std::path::absolute(dir).map_err(|e| format!("`{shown}`: {e}"))?;
    courier_ftp_core::local::local_to_remote(&absolute).map_err(|e| e.to_string())
}

/// `url` with any password replaced by `****`, for error messages.
pub(crate) fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, _)) => format!("{scheme}://{user}:****@{host}{path}"),
            None => url.to_owned(),
        },
        None => url.to_owned(),
    }
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// Generate the man page or shell completions (used by packaging)
    Generate {
        #[command(subcommand)]
        what: Generate,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum Generate {
    /// Write the man page (courier-ftp.1) to stdout or into a directory
    Man {
        /// Directory to write courier-ftp.1 into instead of stdout
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
    /// Write a shell completion script to stdout
    Completions {
        /// The shell to generate completions for
        shell: Shell,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

/// Run `courier-ftp generate …`, writing to `out` unless a directory is given.
pub(crate) fn generate(what: &Generate, out: &mut dyn Write) -> std::io::Result<()> {
    let mut cmd = Cli::command();
    match what {
        Generate::Man { out_dir } => {
            let mut page = Vec::new();
            clap_mangen::Man::new(cmd).render(&mut page)?;
            match out_dir {
                Some(dir) => {
                    std::fs::create_dir_all(dir)?;
                    std::fs::write(dir.join("courier-ftp.1"), page)?;
                }
                None => out.write_all(&page)?,
            }
        }
        Generate::Completions { shell } => {
            let shell = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
                Shell::Powershell => clap_complete::Shell::PowerShell,
            };
            clap_complete::generate(shell, &mut cmd, "courier-ftp", out);
        }
    }
    Ok(())
}

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

pub(crate) fn version() -> String {
    let author = clap::crate_authors!();

    let config_dir_path = get_config_dir().display().to_string();
    let data_dir_path = get_data_dir().display().to_string();
    let vault_path = get_data_dir()
        .join(courier_ftp_store::db::DB_FILE_NAME)
        .display()
        .to_string();

    format!(
        "\
{VERSION_MESSAGE}

Authors: {author}

Config directory: {config_dir_path}
Data directory: {data_dir_path}
Vault: {vault_path}"
    )
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::model::Protocol;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn man_page_names_the_binary() {
        let mut out = Vec::new();
        generate(&Generate::Man { out_dir: None }, &mut out).unwrap();
        let page = String::from_utf8(out).unwrap();
        assert!(page.contains(".TH courier-ftp 1"), "{page}");
        assert!(page.contains("generate"));
    }

    #[test]
    fn man_page_into_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let out_dir = Some(dir.path().join("man"));
        generate(&Generate::Man { out_dir }, &mut std::io::sink()).unwrap();
        assert!(dir.path().join("man/courier-ftp.1").is_file());
    }

    #[test]
    fn completions_for_every_shell() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Powershell] {
            let mut out = Vec::new();
            generate(&Generate::Completions { shell }, &mut out).unwrap();
            let script = String::from_utf8(out).unwrap();
            assert!(script.contains("courier-ftp"), "{shell:?}");
        }
    }

    #[test]
    fn debug_flags_parse() {
        let cli = Cli::try_parse_from(["courier-ftp", "--debug", "--debug-level", "3"]).unwrap();
        assert!(cli.debug);
        assert_eq!(cli.debug_level, Some(3));
        assert!(Cli::try_parse_from(["courier-ftp", "--debug-level", "5"]).is_err());
        let cli = Cli::try_parse_from(["courier-ftp"]).unwrap();
        assert!(!cli.debug);
        assert_eq!(cli.debug_level, None);
    }

    #[test]
    fn generate_parses() {
        let cli = Cli::try_parse_from(["courier-ftp", "generate", "completions", "zsh"]).unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Generate {
                what: Generate::Completions { shell: Shell::Zsh }
            })
        );
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec!["courier-ftp"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv)
    }

    fn launch(args: &[&str]) -> Result<Launch, String> {
        parse(args).unwrap().launch()
    }

    #[test]
    fn no_arguments_launch_nothing() {
        let launch = launch(&[]).unwrap();
        assert!(!launch.connects());
        assert!(launch.local_dir.is_none());
        assert!(!launch.password_in_url);
    }

    #[test]
    fn urls_become_connect_requests() {
        let launch = launch(&[
            "sftp://alice@example.com:2222/var/www",
            "ftp://ftp.example.com",
            "ftps://bob@secure.example.com/pub",
            "FTPES://carol@explicit.example.com",
        ])
        .unwrap();
        assert!(launch.connects());
        assert!(!launch.password_in_url);
        let [sftp, ftp, ftps, ftpes] = &launch.urls[..] else {
            panic!("four requests: {:?}", launch.urls);
        };
        assert_eq!(sftp.info.address.protocol, Protocol::Sftp);
        assert_eq!(sftp.info.address.host, "example.com");
        assert_eq!(sftp.info.address.port, 2222);
        assert_eq!(sftp.path.as_ref().map(|p| p.as_str()), Some("/var/www"));
        assert!(matches!(&sftp.info.logon, LogonType::AskForPassword { user } if user == "alice"));
        assert_eq!(ftp.info.address.protocol, Protocol::Ftp);
        assert!(matches!(ftp.info.logon, LogonType::Anonymous));
        assert_eq!(ftps.info.address.protocol, Protocol::FtpsImplicit);
        assert_eq!(ftpes.info.address.protocol, Protocol::FtpsExplicit);
        assert_eq!(ftpes.info.address.host, "explicit.example.com");
    }

    #[test]
    fn a_password_in_a_url_is_flagged_and_redacted() {
        let launch = launch(&["sftp://alice:hunter2@example.com"]).unwrap();
        assert!(launch.password_in_url);
        assert!(matches!(
            &launch.urls[0].info.logon,
            LogonType::Normal { .. }
        ));
        // Debug output never shows it.
        assert!(!format!("{launch:?}").contains("hunter2"));
        assert_eq!(
            redact("sftp://alice:hunter2@example.com/x"),
            "sftp://alice:****@example.com/x"
        );
        assert_eq!(
            redact("sftp://alice@example.com"),
            "sftp://alice@example.com"
        );
        // Errors never repeat it.
        let err = launch_err(&["sftp://alice:hunter2@example.com:99999"]);
        assert!(!err.contains("hunter2"), "{err}");
        assert!(err.contains("alice:****@"), "{err}");
    }

    fn launch_err(args: &[&str]) -> String {
        launch(args).unwrap_err()
    }

    #[test]
    fn logontype_overrides_the_url_login() {
        let ask = launch(&["--logontype", "ask", "sftp://alice:hunter2@example.com"]).unwrap();
        assert!(
            matches!(&ask.urls[0].info.logon, LogonType::AskForPassword { user } if user == "alice")
        );
        let interactive =
            launch(&["--logontype", "interactive", "sftp://alice@example.com"]).unwrap();
        assert!(
            matches!(&interactive.urls[0].info.logon, LogonType::Interactive { user } if user == "alice")
        );
        assert!(parse(&["--logontype", "normal"]).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            launch_err(&["--logontype", "ask", dir.path().to_str().unwrap()]),
            "--logontype needs a server URL"
        );
    }

    #[test]
    fn local_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let want = courier_ftp_core::local::local_to_remote(dir.path()).unwrap();
        assert_eq!(launch(&[path]).unwrap().local_dir, Some(want.clone()));
        assert_eq!(launch(&["-l", path]).unwrap().local_dir, Some(want.clone()));
        let both = launch(&["--local", path, "sftp://a@h"]).unwrap();
        assert_eq!(both.local_dir, Some(want));
        assert_eq!(both.urls.len(), 1);
        // Two local directories, a missing one, a file.
        assert!(launch_err(&["-l", path, path]).contains("only one local directory"));
        assert!(launch_err(&[path, path]).contains("only one local directory"));
        let missing = dir.path().join("missing");
        assert!(launch_err(&[missing.to_str().unwrap()]).contains("local directory"));
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(launch_err(&[file.to_str().unwrap()]).contains("is not a directory"));
    }

    #[test]
    fn bad_urls_are_errors() {
        assert!(launch_err(&["http://example.com"]).contains("unsupported URL scheme `http://`"));
        assert!(launch_err(&["sftp://"]).starts_with("bad URL"));
        assert!(launch_err(&["ftp://host:0"]).starts_with("bad URL"));
    }

    #[test]
    fn sites_and_flags_parse() {
        let cli = parse(&[
            "-s",
            "Work/Production/web01",
            "--site",
            "home",
            "--config-dir",
            "/tmp/c",
            "--data-dir",
            "/tmp/d",
            "--log-file",
            "/tmp/session.log",
            "--no-keyring",
        ])
        .unwrap();
        assert_eq!(cli.sites, ["Work/Production/web01", "home"]);
        assert_eq!(
            cli.config_dir.as_deref(),
            Some(std::path::Path::new("/tmp/c"))
        );
        assert_eq!(
            cli.data_dir.as_deref(),
            Some(std::path::Path::new("/tmp/d"))
        );
        assert_eq!(
            cli.log_file.as_deref(),
            Some(std::path::Path::new("/tmp/session.log"))
        );
        assert!(cli.no_keyring && !cli.no_vault);
        assert_eq!(
            cli.launch().unwrap().sites,
            ["Work/Production/web01", "home"]
        );
        assert!(launch_err(&["--site", " / "]).contains("--site needs a site path"));
        // --no-vault excludes --site and --no-keyring.
        assert!(parse(&["--no-vault"]).unwrap().no_vault);
        assert!(parse(&["--no-vault", "--site", "x"]).is_err());
        assert!(parse(&["--no-vault", "--no-keyring"]).is_err());
        // Unknown flags and missing values.
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--site"]).is_err());
        assert!(parse(&["--local"]).is_err());
        // The old flags still work; -V is ours.
        let cli = parse(&["-t", "8", "-f", "30", "-V"]).unwrap();
        assert_eq!((cli.tick_rate, cli.frame_rate), (8.0, 30.0));
        assert!(cli.version);
        assert!(parse(&["--version"]).unwrap().version);
    }

    #[test]
    fn help_documents_every_flag() {
        let help = Cli::command().render_long_help().to_string();
        for flag in [
            "[URL_OR_PATH]",
            "--site <PATH>",
            "--local <DIR>",
            "--logontype <TYPE>",
            "--config-dir <DIR>",
            "--data-dir <DIR>",
            "--no-vault",
            "--no-keyring",
            "--debug",
            "--debug-level <0-4>",
            "--log-file <FILE>",
            "--no-update-check",
            "--tick-rate",
            "--frame-rate",
            "--version",
            "Examples:",
        ] {
            assert!(help.contains(flag), "{flag} missing from:\n{help}");
        }
    }

    #[test]
    fn version_names_the_vault() {
        let text = version();
        assert!(text.contains("Config directory: "), "{text}");
        assert!(text.contains("Vault: "), "{text}");
        assert!(text.contains("courier-ftp.db"), "{text}");
    }

    #[test]
    fn man_page_and_completions_have_the_new_flags() {
        let mut out = Vec::new();
        generate(&Generate::Man { out_dir: None }, &mut out).unwrap();
        let page = String::from_utf8(out).unwrap();
        for flag in ["site", "local", "no\\-vault", "log\\-file", "URL_OR_PATH"] {
            assert!(page.contains(flag), "{flag} missing from the man page");
        }
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Powershell] {
            let mut out = Vec::new();
            generate(&Generate::Completions { shell }, &mut out).unwrap();
            let script = String::from_utf8(out).unwrap();
            for flag in [
                "site",
                "local",
                "no-vault",
                "no-keyring",
                "logontype",
                "data-dir",
            ] {
                assert!(script.contains(flag), "{flag} missing for {shell:?}");
            }
        }
    }
}

use std::{io::Write, path::PathBuf};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

use crate::config::{get_config_dir, get_data_dir};

#[derive(Parser, Debug)]
#[command(name = "courier-ftp", author, version = version(), about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Tick rate, i.e. number of ticks per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 4.0)]
    pub(crate) tick_rate: f64,

    /// Frame rate, i.e. number of frames per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 60.0)]
    pub(crate) frame_rate: f64,
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

    // let current_exe_path = PathBuf::from(clap::crate_name!()).display().to_string();
    let config_dir_path = get_config_dir().display().to_string();
    let data_dir_path = get_data_dir().display().to_string();

    format!(
        "\
{VERSION_MESSAGE}

Authors: {author}

Config directory: {config_dir_path}
Data directory: {data_dir_path}"
    )
}

#[cfg(test)]
mod tests {
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
    fn generate_parses() {
        let cli = Cli::try_parse_from(["courier-ftp", "generate", "completions", "zsh"]).unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Generate {
                what: Generate::Completions { shell: Shell::Zsh }
            })
        );
    }
}

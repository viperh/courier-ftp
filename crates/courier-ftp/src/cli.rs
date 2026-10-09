use clap::Parser;

use crate::paths::AppPaths;

#[derive(Parser, Debug)]
// The version string names the resolved directories, so `main` sets it at runtime
// (`Cli::command().version(version(&paths))`).
#[command(author, about)]
pub(crate) struct Cli {
    /// Tick rate, i.e. number of ticks per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 4.0)]
    pub tick_rate: f64,

    /// Frame rate, i.e. number of frames per second
    #[arg(short, long, value_name = "FLOAT", default_value_t = 60.0)]
    pub frame_rate: f64,
}

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

/// The `--version` text: build info and the resolved directories.
pub(crate) fn version(paths: &AppPaths) -> String {
    let author = clap::crate_authors!();

    let config_dir_path = paths.config_dir.display();
    let data_dir_path = paths.data_dir.display();
    let cache_dir_path = paths.cache_dir.display();

    format!(
        "\
{VERSION_MESSAGE}

Authors: {author}

Config directory: {config_dir_path}
Data directory: {data_dir_path}
Cache directory: {cache_dir_path}"
    )
}

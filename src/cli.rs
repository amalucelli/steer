// The terminal surface: the argument grammar, and the commands a person runs by
// hand. Everything under here writes to stdout for a reader; the hook path is
// the other half of the binary and shares none of it.
//
// A command owns its own reporting, since what a report is for differs per
// command — `check` explains one decision, `replay` counts many, `suggest`
// weighs evidence. What they share is the vocabulary: `ink` for colour and
// column alignment, `render` for spelling a rule back the way its config does.

mod check;
mod ink;
mod render;
mod replay;
mod suggest;
mod validate;

pub use check::check;
pub use replay::replay_cmd;
pub use suggest::suggest_cmd;
pub use validate::validate;

use crate::{config, Agent, Event};
use anyhow::{bail, Context, Result};
use clap::builder::styling::{AnsiColor, Styles};
use clap::{ArgAction, Parser, Subcommand};
use ink::Ink;

// `task install` sets STEER_DIRTY so a locally built binary is distinguishable
// from a released one that happens to carry the same crate version.
const VERSION: &str = match option_env!("STEER_DIRTY") {
    Some(_) => concat!(env!("CARGO_PKG_VERSION"), "-dirty"),
    None => env!("CARGO_PKG_VERSION"),
};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default());

const AFTER_HELP: &str = "Examples:
  steer check 'grep -rn foo src'
  steer hook --event PreToolUse < payload.json
  steer validate

hook detects the harness from the payload when --agent is omitted.
check evaluates every rule whatever its harness gate, and takes its command verbatim.";

#[derive(Parser)]
#[command(
    name = "steer",
    about = env!("CARGO_PKG_DESCRIPTION"),
    version = VERSION,
    disable_version_flag = true,
    styles = STYLES,
    after_help = AFTER_HELP,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print version
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    _version: (),

    #[command(subcommand)]
    pub command: Sub,
}

#[derive(Subcommand)]
pub enum Sub {
    /// Read a hook payload on stdin, decide on stdout
    Hook {
        #[arg(long)]
        event: Event,
        #[arg(long)]
        agent: Option<Agent>,
    },
    /// Dry-run a Bash command through the rules
    Check {
        /// The command line to evaluate, as one argument or as words
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Re-run the current rules over the logged calls and report what changed
    Replay {
        /// Only consider calls from the last window: 30m, 6h, 2d, 1w. A bare
        /// number is days
        #[arg(long, value_name = "AGE", value_parser = window_ms)]
        since: Option<u64>,
    },
    /// Report what the log says is missing: escaped denies, then uncaught shapes
    Suggest {
        /// Only consider calls from the last window: 30m, 6h, 2d, 1w. A bare
        /// number is days
        #[arg(long, value_name = "AGE", value_parser = window_ms)]
        since: Option<u64>,
        /// Record every fix in the config as an escape its rule means to
        /// allow, which is the half a log can answer. Closing one instead is a
        /// rule edit, and the report prints the block for it
        #[arg(long)]
        apply: bool,
        /// Write TOML for one finding to stdout instead: a rule name closes its
        /// escape, a head starts a rule for that shape
        #[arg(long, value_name = "NAME", conflicts_with = "apply")]
        draft: Option<String>,
        /// Every pair behind each fix, and the weak ones the report otherwise
        /// counts in a line
        #[arg(long)]
        all: bool,
    },
    /// Print the effective ruleset, with any problems in it
    Validate,
    /// Write a starter global config
    Init,
}

/// How far back to read, as a window rather than a count of days.
///
/// Checking a rule you just wrote is a question about the last few minutes, and
/// a day of a busy log buries it. A bare number stays days, which is what the
/// flag used to mean.
fn window_ms(text: &str) -> Result<u64, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (count, unit) = text.split_at(split);
    let count: u64 = count
        .parse()
        .map_err(|_| format!("expected a window like 30m, 6h, 2d or 1w, not `{text}`"))?;
    let scale = match unit {
        "" | "d" => 86_400_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "w" => 604_800_000,
        other => return Err(format!("unknown unit `{other}`; use m, h, d or w")),
    };
    Ok(count.saturating_mul(scale))
}

/// An empty log is a real answer; a missing one is not.
fn history(since: Option<u64>) -> Result<Vec<crate::replay::Entry>> {
    let path = crate::log::path().context("neither XDG_STATE_HOME nor HOME is set")?;
    if !path.is_file() {
        bail!("no log at {}; steer writes one as it runs", path.display());
    }
    crate::replay::entries(&path, since)
}

pub fn init() -> Result<i32> {
    let path = config::global_path().context("neither XDG_CONFIG_HOME nor HOME is set")?;
    config::init(&path)?;
    let ink = Ink::new();
    println!("wrote {}", ink.bold(&path.display().to_string()));
    Ok(0)
}

// A hook for Claude Code and Codex that steers tool calls toward the right tool.
//
// Auto mode injects a system-level directive telling the model to search with
// shell `grep` and read with `sed -n`, outranking anything in CLAUDE.md. This
// binary intercepts those calls and redirects them, driven by a rule file
// rather than a growing pile of shell branches.
//
// The split of responsibility across the crate: `shell` turns a command line
// into pipeline segments with their wrappers peeled, `rules` holds the
// predicate language and the engine that runs it, `config` stacks built-in,
// global, and repo-overlay sources, `replay` answers the questions only a
// history can, `hook` speaks the hook protocol, `log` records what was acted
// on, and `cli` is the terminal surface over all of it.

mod cli;
mod config;
mod hook;
mod log;
mod replay;
mod rules;
mod shell;

use clap::Parser;
use cli::{Cli, Sub};
use serde::Deserialize;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "PascalCase")]
pub enum Event {
    PreToolUse,
    PostToolUse,
}

impl Event {
    pub fn as_str(&self) -> &'static str {
        match self {
            Event::PreToolUse => "PreToolUse",
            Event::PostToolUse => "PostToolUse",
        }
    }
}

/// The harness steer is speaking to. Codex copies Claude Code's hook protocol
/// closely enough to share the rule engine, but not its tools or its answer to
/// a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }
}

fn main() {
    // clap answers a parse error by printing usage and exiting 2. The hook path
    // may do neither, so it has to be recognised before clap gets a say.
    let hook_path = std::env::args().nth(1).as_deref() == Some("hook");

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // `use_stderr` is false only for --help and --version, which stay
        // ordinary output even under `hook`.
        Err(err) if hook_path && err.use_stderr() => {
            println!(
                "{}",
                hook::breakage(Event::PreToolUse, &format!("steer: {}", terse(&err)))
            );
            std::process::exit(0);
        }
        Err(err) => err.exit(),
    };

    // Only the hook path is fail-open. `check`, `validate`, and `init` are
    // developer tools and should say so loudly when something is wrong.
    let result = match cli.command {
        Sub::Hook { event, agent } => std::process::exit(run_hook(event, agent)),
        Sub::Check { command } => cli::check(&command),
        Sub::Replay { since } => cli::replay_cmd(since),
        Sub::Suggest {
            since,
            apply,
            draft,
            all,
        } => cli::suggest_cmd(since, apply, draft, all),
        Sub::Validate => cli::validate(),
        Sub::Init => cli::init(),
    };

    let code = match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            2
        }
    };
    std::process::exit(code);
}

/// clap renders an error as several paragraphs: the problem, then a usage block
/// and a `--help` hint. Only the first says anything useful once it is buried in
/// a harness message.
fn terse(err: &clap::Error) -> String {
    let rendered = err.to_string();
    let head = rendered.split("\n\n").next().unwrap_or(&rendered);
    head.trim().trim_start_matches("error: ").trim().to_string()
}

/// Swallows a panic as well as an error. The release profile keeps `unwind` for
/// exactly this: an aborting panic would take down the tool call steer exists
/// to let through.
fn run_hook(event: Event, agent: Option<Agent>) -> i32 {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| hook::run(event, agent)));
    std::panic::set_hook(previous);

    result.unwrap_or_else(|_| {
        println!(
            "{}",
            hook::breakage(
                event,
                "steer: panicked while evaluating rules; call allowed"
            )
        );
        0
    })
}

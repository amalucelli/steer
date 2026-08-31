// A Claude Code hook that steers tool calls toward the right tool.
//
// Auto mode injects a system-level directive telling the model to search with
// shell `grep` and read with `sed -n`, outranking anything in CLAUDE.md. This
// binary intercepts those calls and redirects them, driven by a rule file
// rather than a growing pile of shell branches.
//
// The split of responsibility across the crate: `shell` turns a command line
// into pipeline segments with their wrappers peeled, `rules` holds the
// predicate language and the engine that runs it, `config` stacks built-in,
// global, and repo-overlay sources, `hook` speaks the Claude Code protocol, and
// `log` records what was acted on.

mod config;
mod hook;
mod log;
mod rules;
mod shell;

use anyhow::{bail, Context, Result};
use rules::Outcome;
use serde_json::json;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn parse(name: &str) -> Result<Event> {
        match name {
            "PreToolUse" => Ok(Event::PreToolUse),
            "PostToolUse" => Ok(Event::PostToolUse),
            other => bail!("unsupported --event `{other}`"),
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let subcommand = args.next().unwrap_or_default();
    let args: Vec<String> = args.collect();

    // Only the hook path is fail-open. `check`, `validate`, and `init` are
    // developer tools and should say so loudly when something is wrong.
    if subcommand == "hook" {
        std::process::exit(run_hook(&args));
    }

    let code = match dispatch(&subcommand, &args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            2
        }
    };
    std::process::exit(code);
}

/// Swallows a panic as well as an error. The release profile keeps `unwind` for
/// exactly this: an aborting panic would take down the tool call steer exists
/// to let through.
fn run_hook(args: &[String]) -> i32 {
    let event = match parse_event(args) {
        Ok(event) => event,
        Err(err) => {
            println!(
                "{}",
                hook::breakage(Event::PreToolUse, &format!("steer: {err:#}"))
            );
            return 0;
        }
    };

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| hook::run(event)));
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

fn parse_event(args: &[String]) -> Result<Event> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--event" {
            let name = iter.next().context("--event requires an event name")?;
            return Event::parse(name);
        }
        if let Some(name) = arg.strip_prefix("--event=") {
            return Event::parse(name);
        }
    }
    bail!("hook requires --event PreToolUse|PostToolUse")
}

fn dispatch(subcommand: &str, args: &[String]) -> Result<i32> {
    match subcommand {
        "check" => check(args),
        "validate" => validate(),
        "init" => init(),
        _ => Ok(usage()),
    }
}

fn usage() -> i32 {
    eprintln!(
        "usage: steer <hook|check|validate|init>\n\
         \n\
         hook --event PreToolUse|PostToolUse   read a hook payload on stdin, decide on stdout\n\
         check '<command>'                     dry-run a Bash command through the rules\n\
         validate                              report problems in every config source\n\
         init                                  write a starter global config"
    );
    2
}

fn check(args: &[String]) -> Result<i32> {
    let command = args.join(" ");
    if command.trim().is_empty() {
        bail!("check requires a command, e.g. steer check 'grep -rn foo src'");
    }
    let cwd = std::env::current_dir()?;
    let ruleset = config::load(&cwd)?;
    let tool_input = json!({ "command": command });

    println!("command  {command}");
    println!("segments");
    for segment in shell::lex(&command) {
        let wrappers = if segment.wrappers.is_empty() {
            String::new()
        } else {
            format!("  wrappers={:?}", segment.wrappers)
        };
        println!(
            "  head={} args={:?} pipeline_start={} depth={}{wrappers}",
            segment.head, segment.args, segment.pipeline_start, segment.depth
        );
    }

    let decision = rules::evaluate(&ruleset, "Bash", &tool_input);
    println!(
        "matched  {}",
        if decision.fired.is_empty() {
            "-".to_string()
        } else {
            decision.fired.join(", ")
        }
    );
    for (name, why) in &decision.skipped {
        println!("held     {name}: {why}");
    }
    println!("action   {}", decision.outcome.as_str());
    if let Some(command) = &decision.updated_command {
        println!("rewrite  {command}");
    }
    if !decision.message.is_empty() {
        println!("message");
        for line in decision.message.lines() {
            println!("  {line}");
        }
    }
    Ok(if decision.outcome == Outcome::Deny {
        1
    } else {
        0
    })
}

fn validate() -> Result<i32> {
    let cwd = std::env::current_dir()?;
    for source in config::sources(&cwd)? {
        println!("source   {}", source.label);
    }
    let problems = config::validate(&cwd)?;
    for problem in &problems {
        println!("problem  {}: {}", problem.location, problem.detail);
    }
    if problems.is_empty() {
        let count = config::load(&cwd)?.len();
        println!("ok       {count} rules");
        return Ok(0);
    }
    Ok(1)
}

fn init() -> Result<i32> {
    let path = config::global_path().context("neither XDG_CONFIG_HOME nor HOME is set")?;
    config::init(&path)?;
    println!("wrote {}", path.display());
    Ok(0)
}

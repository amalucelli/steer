// The hook boundary: payload in on stdin, the harness's own response back out
// on whichever channel it reads — stdout for all but Windsurf, which takes the
// exit code with the reason on stderr. What a payload looks like and what a
// decision reads as belong to the descriptor in `harness`; this file owns the
// sequence between them.
//
// Nothing here is allowed to block a tool call it did not mean to block. Every
// failure path — unreadable stdin, malformed JSON, a broken config, a panic
// caught upstream — exits 0 with a `systemMessage`, because a hook that hard
// fails takes out every Bash call in every session including the ones needed to
// debug it.
//
// The breakage envelope writes `systemMessage` at the top level and nested
// inside `hookSpecificOutput`: it runs before the harness is known, and
// harnesses document opposite placements.

use crate::rules::{self, Outcome};
use crate::{config, harness, log, Agent, Event};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;

/// The payload fields steer only records. Everything a decision depends on —
/// the tool, its input, the working directory — is addressed through the
/// descriptor's ingest instead, because the key each arrives under is the
/// harness's choice.
///
/// `session_id` is Claude Code's spelling and several harnesses use another;
/// where they do, the log line carries no session and nothing else changes.
#[derive(Debug, Default, Deserialize)]
pub struct Payload {
    #[serde(default)]
    pub session_id: Option<String>,
    /// Undocumented but present for subagent calls; logged when it shows up.
    #[serde(default)]
    pub agent_type: Option<String>,
}

/// The exit code is the decision on Windsurf and ignored everywhere else, so a
/// failure path exits 0: a harness that reads the code has no way to tell a
/// deny from steer falling over.
pub fn run(event: Event, agent: Option<Agent>) -> i32 {
    let answer = match decide(event, agent) {
        Ok(answer) => answer,
        Err(err) => {
            let message = format!("steer: {err:#}");
            println!("{}", breakage(event, &message));
            // Also on stderr: the envelope above is a guess, and a harness that
            // reads only the exit code and stderr would otherwise learn nothing
            // about a steer that fell over.
            eprintln!("{message}");
            return 0;
        }
    };
    if let Some(stdout) = answer.stdout {
        println!("{stdout}");
    }
    if let Some(stderr) = answer.stderr {
        eprintln!("{stderr}");
    }
    answer.code
}

pub fn breakage(event: Event, message: &str) -> String {
    json!({
        "systemMessage": message,
        "hookSpecificOutput": {
            "hookEventName": event.as_str(),
            "systemMessage": message,
        }
    })
    .to_string()
}

fn decide(event: Event, flag: Option<Agent>) -> Result<harness::Answer> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("reading the hook payload from stdin")?;
    let mut raw: Value = serde_json::from_str(&text).context("parsing the hook payload")?;
    // These two fields only reach the log, so a harness spelling one with an
    // unexpected type costs the log line rather than the decision.
    let payload = Payload::deserialize(&raw).unwrap_or_default();
    let agent = flag.with_context(|| {
        format!(
            "no harness named; register the hook with --agent {}",
            harness::names()
        )
    })?;
    let harness = harness::of(agent);

    // The payload's working directory is the session's, and the only thing that
    // can say where the workspace is; a rule that needs it declines when it is
    // missing. Config discovery is a different question and falls back to the
    // process cwd.
    let workspace = harness.ingest.workspace(&raw);
    let config_cwd = match &workspace {
        Some(cwd) => cwd.clone(),
        None => std::env::current_dir()?,
    };
    let name = harness.ingest.tool_name(&raw);
    let tool_name = harness.ingest.canonical(name).unwrap_or(name).to_string();
    // The harness's shape is what a rewrite has to be handed back in, so the
    // input the rules read is a second, canonical copy of it.
    let raw_input = harness.ingest.read(&mut raw);
    let tool_input = harness.ingest.normalize(raw_input.clone());

    let mut ruleset = config::load(&config_cwd, config::Origin::Stack)?;
    // Before the filters below, which would hide a dead rule behind a gate that
    // was never the reason it stopped firing. `validate` exits 1 on the same
    // finding; here it can only be said.
    let note = dead_gates(&ruleset);
    // Denying or rewriting a call that already ran means nothing, so after the
    // fact only context injection is left.
    if event == Event::PostToolUse {
        ruleset.retain(|rule| matches!(rule.spec.action, rules::Action::Context { .. }));
    }
    ruleset.retain(|rule| rule.spec.dropped_for(agent).is_none());

    let decision = rules::evaluate(
        &ruleset,
        &tool_name,
        &tool_input,
        workspace.as_deref(),
        Some(agent),
    );
    // An allowed shell call is the other half of a deny: a rule the model worked
    // around is only visible next to the command it ran instead. Allowed calls
    // to other tools stay unlogged, which keeps edit and write payloads — whole
    // file contents — off disk.
    if decision.outcome != Outcome::Allow || tool_name == "shell" {
        log::record(
            event,
            agent,
            &payload,
            workspace.as_deref(),
            &tool_name,
            &tool_input,
            &decision,
        );
    }
    Ok(harness.render(event, &raw_input, &decision, note.as_deref()))
}

/// One line for however many rules in the stack name a tool or an input field
/// ingest renames. They match nothing and are invisible in the log for the same
/// reason, so the response is the only place left to say it.
///
/// Summary rather than a line per rule: this rides every tool call until the
/// config is fixed, and a near-identical sentence per rule spends the model's
/// context for nothing. `validate` is where the file and line of each one lives.
fn dead_gates(ruleset: &[rules::Rule]) -> Option<String> {
    let dead: Vec<_> = ruleset
        .iter()
        .filter_map(|rule| {
            let (gate, to) = rule.spec.dead_gate()?;
            Some((rule.spec.name.as_str(), gate, to))
        })
        .collect();
    match dead.as_slice() {
        [] => None,
        // One is the case someone is most likely mid-edit on, so it carries the
        // fix instead of sending them elsewhere for a one-word answer.
        [(name, gate, to)] => Some(format!(
            "steer: `{name}` names `{gate}`, which ingest renames to `{to}`, so it never matches."
        )),
        [(name, ..), rest @ ..] => Some(format!(
            "steer: `{name}` and {} more name a tool or a field ingest renames, so they never match. Run `steer validate`.",
            rest.len()
        )),
    }
}

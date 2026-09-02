// The hook boundary: payload in on stdin, `hookSpecificOutput` out on stdout.
// Claude Code and Codex speak close enough to the same protocol to share it;
// where they differ, the agent decides.
//
// Nothing here is allowed to block a tool call it did not mean to block. Every
// failure path — unreadable stdin, malformed JSON, a broken config, a panic
// caught upstream — exits 0 with a `systemMessage`, because a hook that hard
// fails takes out every Bash call in every session including the ones needed to
// debug it.
//
// `additionalContext` and `systemMessage` are nested inside `hookSpecificOutput`
// on purpose; at the top level Claude Code drops them silently. Codex documents
// the opposite placement, so the breakage path writes both — it also runs before
// the agent is known.

use crate::log;
use crate::rules::{self, Decision, Outcome};
use crate::{config, Agent, Event};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
pub struct Payload {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    /// Undocumented but present for subagent calls; logged when it shows up.
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
}

/// Claude Code keeps transcripts under `~/.claude/projects/` and Codex under
/// `~/.codex/sessions/`; failing that, `turn_id` is documented on Codex
/// turn-scoped events and has no Claude Code equivalent. `None` rather than a
/// default, because the wrong ruleset fails silently inside the model's context.
pub fn detect(payload: &Payload) -> Option<Agent> {
    // Components rather than a substring, so a checkout at
    // `~/src/.claude-experiments` is not a signal.
    let from_transcript = payload.transcript_path.as_ref().and_then(|path| {
        Path::new(path)
            .components()
            .find_map(|component| match component.as_os_str().to_str() {
                Some(".codex") => Some(Agent::Codex),
                Some(".claude") => Some(Agent::Claude),
                _ => None,
            })
    });
    from_transcript.or_else(|| payload.turn_id.is_some().then_some(Agent::Codex))
}

pub fn run(event: Event, agent: Option<Agent>) -> i32 {
    match decide(event, agent) {
        Ok(output) => {
            if let Some(output) = output {
                println!("{output}");
            }
        }
        Err(err) => {
            println!("{}", breakage(event, &format!("steer: {err:#}")));
        }
    }
    0
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

fn decide(event: Event, flag: Option<Agent>) -> Result<Option<String>> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("reading the hook payload from stdin")?;
    let payload: Payload = serde_json::from_str(&raw).context("parsing the hook payload")?;
    let agent = flag
        .or_else(|| detect(&payload))
        .context("cannot tell which harness sent this payload; pass --agent claude|codex")?;

    // The payload's cwd is the session's, and the only thing that can say where
    // the workspace is; a rule that needs it declines when it is missing. Config
    // discovery is a different question and falls back to the process cwd.
    let workspace = payload.cwd.as_deref().map(PathBuf::from);
    let config_cwd = match &workspace {
        Some(cwd) => cwd.clone(),
        None => std::env::current_dir()?,
    };
    let tool_name = payload.tool_name.clone().unwrap_or_default();
    let tool_input = payload.tool_input.clone().unwrap_or_else(|| json!({}));

    let mut ruleset = config::load(&config_cwd)?;
    // Denying or rewriting a call that already ran means nothing, so after the
    // fact only context injection is left.
    if event == Event::PostToolUse {
        ruleset.retain(|rule| matches!(rule.spec.action, rules::Action::Context { .. }));
    }
    ruleset.retain(|rule| rule.spec.allows(agent));

    let decision = rules::evaluate(
        &ruleset,
        &tool_name,
        &tool_input,
        workspace.as_deref(),
        Some(agent),
    );
    // An allowed Bash call is the other half of a deny: a rule the model worked
    // around is only visible next to the command it ran instead. Allowed calls
    // to other tools stay unlogged, which keeps Edit and Write payloads — whole
    // file contents — off disk.
    if decision.outcome != Outcome::Allow || tool_name == "Bash" {
        log::record(event, agent, &payload, &tool_name, &tool_input, &decision);
    }
    Ok(render(event, agent, &tool_input, &decision))
}

fn render(event: Event, agent: Agent, tool_input: &Value, decision: &Decision) -> Option<String> {
    let mut fields = Map::new();
    fields.insert("hookEventName".into(), json!(event.as_str()));

    match decision.outcome {
        // Silence is the allow: exit 0 with no stdout leaves the normal
        // permission flow untouched.
        Outcome::Allow => return None,
        Outcome::Deny => {
            fields.insert("permissionDecision".into(), json!("deny"));
            fields.insert("permissionDecisionReason".into(), json!(decision.message));
        }
        Outcome::Rewrite => {
            let command = decision.updated_command.clone()?;
            match agent {
                Agent::Claude => {
                    let mut updated = tool_input.clone();
                    updated
                        .as_object_mut()?
                        .insert("command".into(), json!(command));
                    // No `permissionDecision` alongside it: force-approving
                    // here would route a rewritten command around the
                    // permission classifier.
                    fields.insert("updatedInput".into(), updated);
                    if !decision.message.is_empty() {
                        fields.insert("systemMessage".into(), json!(decision.message));
                    }
                }
                // Codex accepts `updatedInput` only together with an approval,
                // and its `ask` decision is unimplemented, so there is no way
                // to edit the call and still route it through the user.
                Agent::Codex => {
                    let guidance = format!("Run this instead:\n\n  {command}");
                    let reason = if decision.message.is_empty() {
                        guidance
                    } else {
                        format!("{}\n\n{guidance}", decision.message)
                    };
                    fields.insert("permissionDecision".into(), json!("deny"));
                    fields.insert("permissionDecisionReason".into(), json!(reason));
                }
            }
        }
        Outcome::Context => {
            fields.insert("additionalContext".into(), json!(decision.message));
        }
    }
    Some(json!({ "hookSpecificOutput": Value::Object(fields) }).to_string())
}

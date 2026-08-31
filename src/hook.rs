// The Claude Code hook boundary: payload in on stdin, `hookSpecificOutput` out
// on stdout.
//
// Nothing here is allowed to block a tool call it did not mean to block. Every
// failure path — unreadable stdin, malformed JSON, a broken config, a panic
// caught upstream — exits 0 with a `systemMessage`, because a hook that hard
// fails takes out every Bash call in every session including the ones needed to
// debug it.
//
// `additionalContext` and `systemMessage` are nested inside `hookSpecificOutput`
// on purpose; at the top level Claude Code drops them silently.

use crate::log;
use crate::rules::{self, Decision, Outcome};
use crate::{config, Event};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::PathBuf;

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
}

pub fn run(event: Event) -> i32 {
    match decide(event) {
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
        "hookSpecificOutput": {
            "hookEventName": event.as_str(),
            "systemMessage": message,
        }
    })
    .to_string()
}

fn decide(event: Event) -> Result<Option<String>> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("reading the hook payload from stdin")?;
    let payload: Payload = serde_json::from_str(&raw).context("parsing the hook payload")?;

    let cwd = payload
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    let tool_name = payload.tool_name.clone().unwrap_or_default();
    let tool_input = payload.tool_input.clone().unwrap_or_else(|| json!({}));

    let mut ruleset = config::load(&cwd)?;
    // Denying or rewriting a call that already ran means nothing, so after the
    // fact only context injection is left.
    if event == Event::PostToolUse {
        ruleset.retain(|rule| matches!(rule.spec.action, rules::Action::Context { .. }));
    }

    let decision = rules::evaluate(&ruleset, &tool_name, &tool_input);
    if decision.outcome != Outcome::Allow {
        log::record(event, &payload, &tool_name, &tool_input, &decision);
    }
    Ok(render(event, &tool_input, &decision))
}

fn render(event: Event, tool_input: &Value, decision: &Decision) -> Option<String> {
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
            let mut updated = tool_input.clone();
            updated
                .as_object_mut()?
                .insert("command".into(), json!(command));
            // No `permissionDecision` alongside it: force-approving here would
            // route a rewritten command around the permission classifier.
            fields.insert("updatedInput".into(), updated);
            if !decision.message.is_empty() {
                fields.insert("systemMessage".into(), json!(decision.message));
            }
        }
        Outcome::Context => {
            fields.insert("additionalContext".into(), json!(decision.message));
        }
    }
    Some(json!({ "hookSpecificOutput": Value::Object(fields) }).to_string())
}

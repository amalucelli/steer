// Append-only JSON-lines record of everything steer acted on, plus every Bash
// call it allowed, so a surprising deny can be traced back to the rule that
// produced it without re-running the session.
//
// A write failure is swallowed: losing a log line is not a reason to interfere
// with a tool call.

use crate::hook::Payload;
use crate::rules::Decision;
use crate::{Agent, Event};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME")?)
            .join(".local")
            .join("state"),
    };
    Some(base.join("steer").join("steer.jsonl"))
}

pub fn record(
    event: Event,
    agent: Agent,
    payload: &Payload,
    tool_name: &str,
    tool_input: &Value,
    decision: &Decision,
) {
    let entry = json!({
        "ts_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default(),
        "event": event.as_str(),
        "outcome": decision.outcome.as_str(),
        "rules": decision.fired,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "agent_type": payload.agent_type,
        // The harness; `agent_type` is the subagent profile, a different axis.
        "harness": agent.as_str(),
        "session_id": payload.session_id,
        "cwd": payload.cwd,
        "updated_command": decision.updated_command,
    });

    let Some(path) = path() else { return };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{entry}");
    }
}

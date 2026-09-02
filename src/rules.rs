// The predicate language and the engine that runs it.
//
// A tool call arrives, and this module answers with one decision. Getting there
// takes four steps, each of which owns a file: `spec` is the rule as its config
// writes it, `compile` turns that into something that can be asked a question,
// `document` projects the payload into what the predicates read, and `rewrite`
// edits the command line where a rule says to. `trace` is the fifth and answers
// a different question — not what happened, but why.
//
// Two shapes carry most of the design. The first belongs to `compile`: blocks
// are OR'd and the conditions inside one are AND'd against a single binding,
// which is what makes correlation across pipeline segments impossible by
// construction.
//
// The second is here. A rewrite is gated on its replacement binary existing, in
// the engine rather than per rule. `trash` is absent from the Linux VMs, and a
// `trash-over-rm` rewrite that fired there would turn every delete into a
// missing command.

mod compile;
mod document;
mod rewrite;
mod spec;
mod trace;

pub use compile::Rule;
pub use document::in_workspace;
pub use rewrite::on_path;
pub use spec::{Action, MatchBlock, Message, Outcome, Predicate, RuleSpec, TestSpec};
pub use trace::{trace, trace_at, Checked, Trace};

use crate::shell;
use crate::Agent;
use document::{document, enrich};
use rewrite::splice;
use serde_json::{json, Value};
use std::path::Path;

pub struct Decision {
    pub outcome: Outcome,
    pub message: String,
    /// Present only for a rewrite, as the replacement `command`.
    pub updated_command: Option<String>,
    /// Names of the rules that produced the decision, strongest action first.
    pub fired: Vec<String>,
    /// Rules that matched but were held back, with why, for `steer check`.
    pub skipped: Vec<(String, String)>,
}

/// Evaluates every rule and lets the most restrictive action decide. File order
/// carries no meaning, so a repo overlay can never weaken a global deny.
pub fn evaluate(
    rules: &[Rule],
    tool_name: &str,
    tool_input: &Value,
    cwd: Option<&Path>,
    agent: Option<Agent>,
) -> Decision {
    let command = tool_input
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (segments, doc) = document(tool_name, tool_input, cwd);

    let mut fired: Vec<&Rule> = Vec::new();
    let mut skipped = Vec::new();

    for rule in rules {
        if !rule.matches(&doc) {
            continue;
        }
        match &rule.spec.action {
            Action::Rewrite {
                replace_head,
                drop_args,
                add_args,
                ..
            } => {
                // Only a head replacement names a binary; an argument-only
                // rewrite has nothing to look up.
                if let Some(head) = replace_head {
                    if !on_path(head) {
                        skipped.push((rule.spec.name.clone(), format!("`{head}` is not on PATH")));
                        continue;
                    }
                }
                // An unclosed heredoc leaves steer guessing where a command
                // ends and body text begins. Bash still runs such a line — it
                // warns and treats EOF as the delimiter — so a rewrite aimed at
                // a misread body would be written into whatever file the
                // heredoc feeds. Deny and context are safe here because they
                // change no bytes; only rewriting is.
                if segments.iter().any(|s| s.recovered) {
                    skipped.push((
                        rule.spec.name.clone(),
                        "the command did not parse cleanly (unclosed heredoc)".into(),
                    ));
                    continue;
                }
                // A rule that matches but cannot be spliced has not fired, and
                // must not contribute its reason to the message either.
                let hits = rule.matching_segments(&doc);
                match splice(
                    command,
                    &segments,
                    &hits,
                    replace_head.as_deref(),
                    drop_args,
                    add_args,
                ) {
                    Some(_) => fired.push(rule),
                    None => skipped.push((
                        rule.spec.name.clone(),
                        "matched only nested or unspannable text".into(),
                    )),
                }
            }
            _ => fired.push(rule),
        }
    }

    if fired.is_empty() {
        return Decision {
            outcome: Outcome::Allow,
            message: String::new(),
            updated_command: None,
            fired: Vec::new(),
            skipped,
        };
    }

    fired.sort_by_key(|rule| std::cmp::Reverse(rule.spec.action.outcome()));
    let outcome = fired[0].spec.action.outcome();

    // Every matching rule contributes its reason, so a user sees the whole
    // story rather than only the rule that happened to win.
    let message = fired
        .iter()
        .map(|rule| rule.spec.action.message().text(agent).trim().to_string())
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");

    // Rewrites compose: each applies to the command the previous one produced,
    // so the segments and the document are rebuilt on every pass.
    let mut updated_command = None;
    if outcome == Outcome::Rewrite {
        let mut current = command.to_string();
        let mut input = tool_input.clone();
        for rule in &fired {
            let Action::Rewrite {
                replace_head,
                drop_args,
                add_args,
                ..
            } = &rule.spec.action
            else {
                continue;
            };
            if let Some(fields) = input.as_object_mut() {
                fields.insert("command".into(), json!(current));
            }
            let segments = shell::lex(&current);
            let doc = enrich(tool_name, &input, &segments, cwd);
            let hits = rule.matching_segments(&doc);
            if let Some(next) = splice(
                &current,
                &segments,
                &hits,
                replace_head.as_deref(),
                drop_args,
                add_args,
            ) {
                current = next;
            }
        }
        updated_command = Some(current);
    }

    Decision {
        outcome,
        message,
        updated_command,
        fired: fired.iter().map(|r| r.spec.name.clone()).collect(),
        skipped,
    }
}

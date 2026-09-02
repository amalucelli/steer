// One command, evaluated and explained.
//
// The engine answers with an outcome, which is the least interesting half of
// what a person running this wants. The rest is why: how the line lexed, which
// block of which rule bound to which segment, and — when nothing fired — the
// single condition that stopped the rule that came closest.

use super::ink::{paint_outcome, row, Ink};
use super::render::render_op;
use crate::rules::Outcome;
use crate::{config, rules, shell};
use anyhow::{bail, Result};
use serde_json::json;

// Harness-agnostic on purpose: what a rule matches is the question here, and
// that does not change between harnesses. The `agents` gate, and the rendering
// that follows from it, belong to the hook path.
pub fn check(rest: &[String]) -> Result<i32> {
    let command = rest.join(" ");
    // `required` guarantees an argument, not a non-empty one.
    if command.trim().is_empty() {
        bail!("check requires a command, e.g. steer check 'grep -rn foo src'");
    }
    let cwd = std::env::current_dir()?;
    let ruleset = config::load(&cwd)?;
    let tool_input = json!({ "command": command });

    let ink = Ink::new();
    row(&ink, "command", &ink.bold(&command));
    row(&ink, "cwd", &cwd.display().to_string());
    row(&ink, "segments", "");
    for segment in shell::lex(&command) {
        let wrappers = if segment.wrappers.is_empty() {
            String::new()
        } else {
            format!("  wrappers={:?}", segment.wrappers)
        };
        let flag = |name: &str, value: bool| {
            let text = format!("{name}={value}");
            match value {
                true => ink.green(&text),
                false => ink.red(&text),
            }
        };
        println!(
            "  {}={} {}={:?} {} {} {}{}",
            ink.cyan("head"),
            ink.bold(&segment.head),
            ink.cyan("args"),
            segment.args,
            flag("pipeline_start", segment.pipeline_start),
            flag("in_workspace", rules::in_workspace(&cwd, &segment.args)),
            ink.dim(&format!("depth={}", segment.depth)),
            ink.dim(&wrappers)
        );
    }

    // No harness, so a per-harness message reports every copy it carries.
    let decision = rules::evaluate(&ruleset, "Bash", &tool_input, Some(&cwd), None);
    let traces = rules::trace(&ruleset, "Bash", &tool_input, Some(&cwd));
    if decision.fired.is_empty() {
        row(&ink, "matched", &ink.dim("-"));
    }
    // A three-block rule that says only "matched" leaves the reader to work out
    // which of its shapes caught the command.
    for name in &decision.fired {
        let where_ = traces
            .iter()
            .find(|trace| &trace.rule == name)
            .map(|trace| ink.dim(&format!("  (block {}, {})", trace.block, trace.binding)))
            .unwrap_or_default();
        row(&ink, "matched", &format!("{}{where_}", ink.bold(name)));
    }
    for (name, why) in &decision.skipped {
        row(&ink, "held", &ink.yellow(&format!("{name}: {why}")));
    }
    print_nearest(&decision, &traces, &ruleset, &ink);
    row(&ink, "action", &paint_outcome(&ink, decision.outcome));
    if let Some(command) = &decision.updated_command {
        row(&ink, "rewrite", &ink.bold(command));
    }
    if !decision.message.is_empty() {
        row(&ink, "message", "");
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

/// The rules that came closest without firing, and the condition that stopped
/// each. "Nothing matched" is an answer without a reason, and the reason is
/// almost always one condition on one segment.
fn print_nearest(
    decision: &rules::Decision,
    traces: &[rules::Trace],
    ruleset: &[rules::Rule],
    ink: &Ink,
) {
    let mut nearest: Vec<&rules::Trace> = traces
        .iter()
        .filter(|trace| {
            !decision.fired.contains(&trace.rule)
                && trace.on_topic()
                && (1..=2).contains(&trace.missing())
        })
        .collect();
    nearest.sort_by_key(|trace| (trace.missing(), trace.rule.clone()));
    nearest.truncate(3);

    for trace in nearest {
        let Some(rule) = ruleset.iter().find(|rule| rule.spec.name == trace.rule) else {
            continue;
        };
        let block = &rule.spec.blocks[trace.block];
        row(
            ink,
            "nearest",
            &format!(
                "{}  {}",
                ink.bold(&trace.rule),
                ink.dim(&format!(
                    "{} of {} · block {}, {}",
                    trace.held(),
                    trace.checks.len(),
                    trace.block,
                    trace.binding
                ))
            ),
        );
        let mut checks: Vec<&rules::Checked> = trace.checks.iter().collect();
        checks.sort_by_key(|check| check.path != "head");
        for check in checks {
            let condition = render_op(&check.path, check.op, &block.conditions[&check.path], ink);
            let (mark, actual) = match check.held {
                true => (ink.green("✓"), String::new()),
                false => (
                    ink.red("✗"),
                    format!("  {}", ink.dim(&format!("actual={}", check.actual))),
                ),
            };
            row(ink, "", &format!("{mark} {condition}{actual}"));
        }
    }
}

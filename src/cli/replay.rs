// What today's rules would do to calls already made.
//
// The engine's own vocabulary — `rewrite → allow` — names a transition between
// two outcomes, and a reader deciding whether to ship a rule is not deciding
// about a transition. They are deciding about a consequence, so the report
// groups by that: what would now be stopped, and what would now go through.

use super::ink::{clip, row, Ink};
use crate::rules::Outcome;
use crate::{config, replay};
use anyhow::Result;

/// Grouped by rule rather than listed flat: what a new rule costs is how many
/// calls it newly catches, and that number is the first thing to read.
pub fn replay_cmd(since: Option<u64>) -> Result<i32> {
    let entries = super::history(since)?;
    let ink = Ink::new();
    let ruleset = config::load(&std::env::current_dir()?)?;
    let changes = replay::replay(&entries, &ruleset);

    let mut stopped: Vec<&replay::Change> = Vec::new();
    let mut through: Vec<&replay::Change> = Vec::new();
    for change in &changes {
        match stricter(&change.was, change.now) {
            true => stopped.push(change),
            false => through.push(change),
        }
    }

    if !changes.is_empty() {
        row(
            &ink,
            "replay",
            &ink.dim("what today's rules would do to calls already made — nothing is written"),
        );
    }
    bucket(
        &ink,
        "stopped",
        "would now be stopped",
        &stopped,
        "read these: a rule catching work you meant to do is a false positive",
    );
    bucket(
        &ink,
        "through",
        "would now go through",
        &through,
        "a rule stopped catching these",
    );

    let replayed = entries.len();
    row(&ink, "", "");
    if changes.is_empty() {
        row(
            &ink,
            "ok",
            &ink.green(&format!("{replayed} calls, none would land differently")),
        );
        return Ok(0);
    }
    // A difference is only about a rule you wrote if the call it disagrees with
    // was decided by the rules you have. Further back it is history: that answer
    // came from whatever the rules were that day, and the log does not say which
    // version that was.
    // Only worth saying when the reader did not scope the read themselves.
    let age = match since {
        Some(_) => String::new(),
        None => {
            let yesterday = replay::now_ms().saturating_sub(86_400_000);
            let today = changes
                .iter()
                .filter(|change| change.ts_ms >= yesterday)
                .count();
            match today {
                0 => format!(
                    " · {}",
                    ink.green("none from the last day, so nothing you just changed")
                ),
                n => format!(" · {}", ink.bold(&format!("{n} from the last day"))),
            }
        }
    };
    row(
        &ink,
        "ok",
        &format!(
            "{replayed} calls, {} would land differently{age}",
            ink.bold(&changes.len().to_string()),
        ),
    );
    Ok(0)
}

/// Whether today's rules answer this call more strictly than the log says they
/// did. The two directions are the only thing a reader has to decide between:
/// a call newly stopped might be a false positive, and one newly let through
/// used to be caught.
fn stricter(was: &str, now: Outcome) -> bool {
    let strength = |outcome: &str| match outcome {
        "deny" => 3,
        "rewrite" => 2,
        "context" => 1,
        _ => 0,
    };
    strength(now.as_str()) > strength(was)
}

/// One consequence, its calls, and what to do about it. Silent when empty: an
/// empty heading is a line a reader has to rule out.
fn bucket(ink: &Ink, label: &str, heading: &str, calls: &[&replay::Change], advice: &str) {
    if calls.is_empty() {
        return;
    }
    row(
        ink,
        label,
        &format!(
            "{:>4}  {}  {}",
            calls.len(),
            ink.bold(heading),
            ink.dim(advice)
        ),
    );
    // The rule leads each line: it is short, it aligns, and it is what the
    // reader is deciding about. The command trails, clipped — a heredoc arrives
    // with its body attached, and a raw newline would break every column below.
    let named = |change: &replay::Change| match change.rules.is_empty() {
        true => change.was_rules.join(", "),
        false => change.rules.join(", "),
    };
    let width = calls
        .iter()
        .take(5)
        .map(|change| named(change).chars().count())
        .max()
        .unwrap_or(0);
    for change in calls.iter().take(5) {
        row(
            ink,
            "",
            &format!(
                "{}  {}",
                ink.dim(&format!("{:<width$}", named(change))),
                clip(&change.command)
            ),
        );
    }
    if calls.len() > 5 {
        row(ink, "", &ink.dim(&format!("… {} more", calls.len() - 5)));
    }
}

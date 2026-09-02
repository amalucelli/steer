// A rule spelled back the way its config spells it.
//
// `validate` prints a whole ruleset and `check` prints the conditions of the
// one rule that came closest, and the two have to agree character for character
// — a reader comparing a near miss against the rule it came from is comparing
// two lines of this output, not two data structures.

use super::ink::{paint_outcome, row, Ink};
use crate::rules;
use std::path::Path;

/// The rule's contract on one line: what it does, and what it is allowed to see.
pub fn headline(spec: &rules::RuleSpec, ink: &Ink) -> String {
    // Naming the replacement binary is the one thing the outcome alone cannot say.
    let action = match &spec.action {
        rules::Action::Rewrite {
            replace_head: Some(head),
            ..
        } => ink.yellow(&format!("rewrite → {head}")),
        action => paint_outcome(ink, action.outcome()),
    };
    let tool = spec.tool.clone().unwrap_or_else(|| "any tool".into());
    let agents = match spec.gated_to() {
        Some(list) => list
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        None => "any agent".into(),
    };
    format!("{action} {}", ink.dim(&format!("· {tool} · {agents}")))
}

pub fn print_rule(spec: &rules::RuleSpec, cwd: &Path, ink: &Ink) {
    if let rules::Action::Rewrite {
        drop_args,
        add_args,
        ..
    } = &spec.action
    {
        if !drop_args.is_empty() {
            row(ink, "  drops", &drop_args.join(" "));
        }
        if !add_args.is_empty() {
            row(ink, "  adds", &add_args.join(" "));
        }
    }
    // A rule fires when any block holds, and a block holds when every condition
    // under it holds against the same binding — so one line per block, with its
    // conditions read as an AND.
    let width = spec
        .blocks
        .iter()
        .map(|block| binding(block).chars().count())
        .max()
        .unwrap_or(0);
    for block in &spec.blocks {
        let binding = ink.dim(&format!("{:<width$}", binding(block)));
        row(
            ink,
            "  match",
            &format!("{binding}  {}", conditions(block, ink)),
        );
    }
    print_examples(spec, cwd, ink);
}

/// The commands the rule claims to fire on and to leave alone. `validate` has
/// already run them by the time these print, so they are assertions rather than
/// comments; a rewrite also shows what it produces, which is the part no list of
/// conditions can say.
fn print_examples(spec: &rules::RuleSpec, cwd: &Path, ink: &Ink) {
    let compiled = rules::Rule::compile(spec.clone()).ok();
    for command in &spec.test.fires {
        let preview = compiled
            .as_ref()
            .and_then(|rule| rule.preview(command, Some(cwd)))
            .filter(|rewritten| rewritten != command)
            .map(|rewritten| format!("  {}  {}", ink.dim("→"), ink.bold(&rewritten)))
            .unwrap_or_default();
        row(ink, "  fires", &format!("{command}{preview}"));
    }
    for command in &spec.test.ignores {
        row(ink, "  ignores", &ink.dim(command));
    }
    for (command, want) in &spec.test.rewrites {
        row(
            ink,
            "  rewrite",
            &format!("{command}  {}  {}", ink.dim("→"), ink.bold(want)),
        );
    }
}

fn binding(block: &rules::MatchBlock) -> String {
    match (&block.any, &block.all) {
        (Some(path), _) => format!("any {path}"),
        (_, Some(path)) => format!("all {path}"),
        _ => "tool input".to_string(),
    }
}

/// The conditions of one block as `check` spells a segment: `key=value` pairs,
/// with the operator carried by the sign. `!` negates, `~` is a glob rather than
/// a literal, and a regex arrives between slashes. Colour separates the three
/// parts, since a block runs its conditions together on one line: the key is
/// cyan, an exclusion red, and a pattern yellow to set it apart from a literal.
fn conditions(block: &rules::MatchBlock, ink: &Ink) -> String {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    for (path, predicate) in &block.conditions {
        for op in operators(predicate) {
            pairs.push((path.as_str(), render_op(path, op, predicate, ink)));
        }
    }
    // `head` is what a reader looks for first; the rest stays alphabetical, as
    // the config's own map ordering leaves it.
    pairs.sort_by_key(|(path, _)| *path != "head");
    pairs
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The operators a condition carries, named as the engine reports them so a
/// trace can ask for the same rendering the `match` line uses.
fn operators(predicate: &rules::Predicate) -> Vec<&'static str> {
    let present: [(&'static str, bool); 6] = [
        ("any_of", predicate.any_of.is_some()),
        ("none_of", predicate.none_of.is_some()),
        ("glob", predicate.glob.is_some()),
        ("none_glob", predicate.none_glob.is_some()),
        ("matches", predicate.matches.is_some()),
        ("is", predicate.is.is_some()),
    ];
    present
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(op, _)| op)
        .collect()
}

pub fn render_op(path: &str, op: &str, predicate: &rules::Predicate, ink: &Ink) -> String {
    let key = ink.cyan(path);
    match op {
        "any_of" => format!(
            "{key}{}{}",
            ink.dim("="),
            list(predicate.any_of.as_deref().unwrap_or_default())
        ),
        "none_of" => format!(
            "{key}{}{}",
            ink.red("!="),
            list(predicate.none_of.as_deref().unwrap_or_default())
        ),
        "glob" => format!(
            "{key}{}{}",
            ink.dim("=~"),
            ink.yellow(&list(predicate.glob.as_deref().unwrap_or_default()))
        ),
        "none_glob" => format!(
            "{key}{}{}",
            ink.red("!~"),
            ink.yellow(&list(predicate.none_glob.as_deref().unwrap_or_default()))
        ),
        "matches" => format!(
            "{key}{}{}",
            ink.dim("="),
            ink.yellow(&format!(
                "/{}/",
                predicate.matches.as_deref().unwrap_or_default()
            ))
        ),
        _ => match predicate.is {
            Some(false) => ink.red(&format!("!{path}")),
            _ => ink.green(path),
        },
    }
}

fn list(values: &[String]) -> String {
    match values {
        [only] => only.clone(),
        many => format!("[{}]", many.join(",")),
    }
}

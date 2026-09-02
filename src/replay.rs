// What the log says about rules that already ran.
//
// The engine answers one call at a time. These are the questions only a history
// can answer: whether a rule about to ship would have fired on work that already
// happened, and whether a rule the model was refused by simply got worked around
// with a spelling nobody wrote a block for.
//
// Both read the same file the hook appends to, and neither writes anything.

use crate::rules::{
    self, Action, MatchBlock, Message, Outcome, Predicate, Rule, RuleSpec, TestSpec,
};
use crate::shell;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A deny and the command that got through are only the same event when they
/// are close together. Further apart, the model moved on to something else.
const ESCAPE_WINDOW_MS: u64 = 60_000;

#[derive(Debug, Deserialize)]
pub struct Entry {
    #[serde(default)]
    pub ts_ms: u64,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

impl Entry {
    /// The command line, for Bash entries only. Every other tool is logged for
    /// its decision, not for anything that can be re-lexed.
    fn command(&self) -> Option<&str> {
        if self.tool_name != "Bash" {
            return None;
        }
        self.tool_input.get("command")?.as_str()
    }
}

/// Skips lines that do not parse rather than failing. The log is append-only
/// across versions of steer, and one entry written by an older schema is not a
/// reason to refuse to read the rest.
pub fn entries(path: &Path, window_ms: Option<u64>) -> Result<Vec<Entry>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cutoff = window_ms.map(|window| now_ms().saturating_sub(window));
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .filter(|entry| cutoff.is_none_or(|cutoff| entry.ts_ms >= cutoff))
        .collect())
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub struct Change {
    pub command: String,
    pub ts_ms: u64,
    pub was: String,
    pub now: Outcome,
    /// The rules that answer now, and the ones that answered then. A change
    /// toward `allow` has none of the first, and the second is the only place
    /// the rule that stopped catching the call is named.
    pub rules: Vec<String>,
    pub was_rules: Vec<String>,
}

/// Every logged command the current ruleset would answer differently.
///
/// This is how a rule gets tested before it ships: write it, replay, and read
/// what it would have done to work that already happened. A rule that fires on
/// forty allowed commands is a false positive found before it costs a session.
///
/// Rules are evaluated whatever their `agents` gate says, the way `check` does
/// — whether a block matches a command is the same question under either
/// harness, and the gate belongs to the rendering that the hook path does.
pub fn replay(entries: &[Entry], ruleset: &[Rule]) -> Vec<Change> {
    let mut changes = Vec::new();
    for entry in entries {
        let Some(command) = entry.command() else {
            continue;
        };
        let input = serde_json::json!({ "command": command });
        let cwd = entry.cwd.as_ref().map(PathBuf::from);
        let decision = rules::evaluate(ruleset, "Bash", &input, cwd.as_deref(), None);
        if decision.outcome.as_str() == entry.outcome {
            continue;
        }
        changes.push(Change {
            command: command.to_string(),
            ts_ms: entry.ts_ms,
            was: entry.outcome.clone(),
            now: decision.outcome,
            rules: decision.fired,
            was_rules: entry.rules.clone(),
        });
    }
    changes
}

pub struct Escape {
    pub denied: String,
    pub rules: Vec<String>,
    pub allowed: String,
    pub gap_s: u64,
    /// The token the two commands have in common, which is the whole reason
    /// they were paired. Reported so the pairing can be judged rather than
    /// taken on faith: `ts:security` is a retry, a shared `head` is a coincidence.
    pub shared: String,
    /// Where the second call ran. `in_workspace` is one of the conditions worth
    /// naming, and it only means anything against the directory it was asked in.
    pub cwd: Option<String>,
}

/// A refusal followed by a command that got through, in the same session and
/// close behind it.
///
/// This is the only place a rule's real failure shows up. A deny on its own
/// reads as the rule working; it is the command the model reached for next that
/// says whether the guidance was followed or routed around. `python3 -` denied
/// and `python3 -c` allowed eight seconds later is one rule with a hole in it,
/// and neither line says so alone.
pub fn escapes(entries: &[Entry]) -> Vec<Escape> {
    // Lexed once rather than per candidate pair: a window used to hold about one
    // entry, and now that every allowed Bash call is logged it holds tens, each
    // of which would otherwise re-lex both sides.
    let lexed: Vec<Fingerprint> = entries
        .iter()
        .map(|entry| match entry.command() {
            Some(command) => fingerprint(command),
            None => Fingerprint {
                head: None,
                operands: Vec::new(),
            },
        })
        .collect();

    let mut found = Vec::new();
    for (i, denied) in entries.iter().enumerate() {
        if denied.outcome != "deny" {
            continue;
        }
        let Some(denied_command) = denied.command() else {
            continue;
        };
        let next = entries[i + 1..]
            .iter()
            .enumerate()
            .take_while(|(_, e)| e.ts_ms.saturating_sub(denied.ts_ms) <= ESCAPE_WINDOW_MS)
            .filter(|(_, e)| e.session_id == denied.session_id && e.outcome == "allow")
            .find_map(|(offset, e)| {
                let allowed_command = e.command()?;
                let shared = retries(&lexed[i], &lexed[i + 1 + offset])?;
                Some((e, allowed_command, shared))
            });
        let Some((next, allowed_command, shared)) = next else {
            continue;
        };
        let escape = Escape {
            denied: denied_command.to_string(),
            rules: denied.rules.clone(),
            allowed: allowed_command.to_string(),
            gap_s: next.ts_ms.saturating_sub(denied.ts_ms) / 1000,
            shared,
            cwd: next.cwd.clone(),
        };
        // The call that got through is the evidence, so it is what identifies
        // the finding. A loop refused three times and rephrased once is one
        // escape, not three, and keying on the deny would report it as three.
        let seen = found
            .iter()
            .any(|other: &Escape| other.allowed == escape.allowed && other.rules == escape.rules);
        if !seen {
            found.push(escape);
        }
    }
    found
}

/// The token that says the second command retries the first, if one does.
///
/// Without this every deny pairs with whatever followed it, and almost none of
/// those are escapes. Two commands are the same attempt when they run the same
/// program — `python3 -` and `python3 -c` — or when they name the same thing:
/// `sed -n … src/hook.rs` and `nl src/hook.rs` share the file.
///
/// The two halves are not weighed alike. A leading command is identity whatever
/// it looks like, but a shared operand has to be distinctive to mean anything:
/// two lines that both say `1` or `build` have nothing to do with each other,
/// and pairing on those fills the report with coincidences.
fn retries(denied: &Fingerprint, allowed: &Fingerprint) -> Option<String> {
    if let (Some(a), Some(b)) = (&denied.head, &allowed.head) {
        if a == b {
            return Some(a.clone());
        }
    }
    allowed
        .operands
        .iter()
        .find(|token| distinctive(token) && denied.operands.contains(*token))
        .cloned()
}

/// Whether a token names something in particular. A path, an extension, or a
/// qualified name carries enough to identify one piece of work; a bare word or
/// a number is shared by half the log.
fn distinctive(token: &str) -> bool {
    token.contains(['/', '.', ':']) || token.chars().count() >= 8
}

/// What two commands are compared on.
///
/// Flags name no subject and are dropped, and so is navigation — a `cd` prefix
/// and its path are shared by everything run in the same directory and would
/// pair all of it. Only the *leading* command counts as identity: a trailing
/// `| head -30` is how output gets shortened rather than what the line is
/// doing, and counting it pairs any two commands that end in the same pager.
struct Fingerprint {
    head: Option<String>,
    operands: Vec<String>,
}

fn fingerprint(command: &str) -> Fingerprint {
    let segments: Vec<_> = shell::lex(command)
        .into_iter()
        .filter(|s| s.head != "cd" && s.head != "pushd")
        .collect();
    Fingerprint {
        head: segments.first().map(|s| s.head.clone()),
        operands: segments
            .into_iter()
            .flat_map(|s| s.args.into_iter().filter(|a| !a.starts_with('-')))
            .collect(),
    }
}

pub struct Shape {
    pub head: String,
    pub count: usize,
    pub example: String,
}

/// Allowed commands grouped by the head that led their pipeline, most frequent
/// first.
///
/// The weakest signal: frequency says what the model reaches for, not what it
/// should have been stopped from reaching for, and that judgement stays with
/// the reader. The head is the same field a rule matches on, so a line here is
/// already most of a `[[rules.match]]` block.
pub fn shapes(entries: &[Entry]) -> Vec<Shape> {
    let mut counts: Vec<Shape> = Vec::new();
    for entry in entries.iter().filter(|e| e.outcome == "allow") {
        let Some(command) = entry.command() else {
            continue;
        };
        let Some(segment) = shell::lex(command)
            .into_iter()
            .find(|s| s.pipeline_start && s.depth == 0)
        else {
            continue;
        };
        match counts.iter_mut().find(|s| s.head == segment.head) {
            Some(shape) => shape.count += 1,
            None => counts.push(Shape {
                head: segment.head,
                count: 1,
                example: command.to_string(),
            }),
        }
    }
    counts.sort_by(|a, b| b.count.cmp(&a.count).then(a.head.cmp(&b.head)));
    counts
}

/// A rule to paste, and the lines of comment that explain what to do with it.
///
/// The draft never carries judgement — whether a shape should be stopped at
/// all, and what to point at instead, stay with the reader. What it carries is
/// the mechanical half: a block that matches, and a `fires` example already
/// known to be true of it, so the first `validate` after pasting means
/// something.
pub struct Draft {
    pub notes: Vec<String>,
    pub spec: RuleSpec,
}

/// What every draft ends on: a rule matching on a command name is a wide thing
/// to deny, and the log that produced the draft is what measures how wide.
fn blast_radius() -> Vec<String> {
    vec![
        String::new(),
        "Paste it, then `steer replay` — it counts every logged call this now".into(),
        "answers differently, which is how wide the rule really is.".into(),
    ]
}

/// A starter rule for a head the log keeps showing, seeded with a real call.
pub fn draft_rule(shape: &Shape) -> Draft {
    let mut notes = vec![
        format!("{} allowed calls led with `{}`.", shape.count, shape.head),
        "Name it for the tool you are steering toward, the way `fff-over-grep`".into(),
        "does, and fill in the message: a deny the model cannot act on is worse".into(),
        "than no rule at all. Add `ignores` for the spellings it must leave alone.".into(),
    ];
    notes.extend(blast_radius());
    Draft {
        notes,
        spec: RuleSpec {
            name: format!("tool-over-{}", shape.head),
            description: String::new(),
            tool: Some("Bash".into()),
            agents: None,
            blocks: vec![segment_block(&shape.head, true)],
            action: Action::Deny {
                message: Message::default(),
            },
            test: TestSpec {
                fires: vec![shape.example.clone()],
                ..TestSpec::default()
            },
        },
    }
}

/// The rule as it would be with the escape closed: the shape that got through
/// added as another block, and the call itself added to `fires`.
///
/// It comes back whole because that is the only pasteable form — a rule is
/// extended by redefining it under the same name, and a bare `[[rules.match]]`
/// appended to a config would attach to whichever rule happens to be last.
///
/// Only for a rule that already names the command. Where it does, the escape is
/// a new *shape* of a command the rule owns, which is what a block is for. Where
/// it does not, appending a block would bolt a new subject onto the rule and
/// would drop every discriminator the existing blocks carry — the caller checks
/// `knows_head` and declines instead.
pub fn draft_extension(spec: &RuleSpec, escape: &Escape) -> Option<Draft> {
    let (_, segment) = rephrase(escape)?;
    let mut extended = spec.clone();
    // Claiming a pipeline start the escape did not have would draft a block
    // that cannot fire on the very call it came from.
    extended
        .blocks
        .push(segment_block(&segment.head, segment.pipeline_start));
    extended.test.fires.push(escape.allowed.clone());

    let mut notes = vec![
        format!(
            "`{}` was refused, and this got through {}s later:",
            spec.name, escape.gap_s
        ),
        format!("  {}", escape.allowed),
        String::new(),
        "The whole rule, with that shape added as a block and the call added to".into(),
        "`fires`. Paste it into your config: a later source replaces a rule of the".into(),
        "same name, which is how a built-in gets extended.".into(),
        String::new(),
    ];
    notes.extend([
        "Then narrow it: the block matches on the command alone, which is wider".into(),
        "than you probably want. The arguments the escape carried:".into(),
    ]);
    notes.push(match segment.args.is_empty() {
        true => "  it took none; `args = { none_glob = [\"*\"] }` is how that is said".into(),
        false => format!("  {}", segment.args.join(" ")),
    });
    notes.extend(blast_radius());
    Some(Draft {
        notes,
        spec: extended,
    })
}

/// The segment of the allowed command that stands in for the denied one.
///
/// The rephrase is rarely the whole line. `cargo build && steer check …` leads
/// with a segment that has nothing to do with the deny, so the one taken is the
/// segment sharing the most with the denied command — the same overlap that
/// paired the two in the first place.
pub fn rephrase(escape: &Escape) -> Option<(usize, shell::Segment)> {
    let denied = fingerprint(&escape.denied);
    let shares =
        |token: &String| denied.head.as_ref() == Some(token) || denied.operands.contains(token);
    shell::lex(&escape.allowed)
        .into_iter()
        .enumerate()
        .filter(|(_, s)| s.depth == 0)
        .max_by_key(|(_, s)| {
            std::iter::once(&s.head)
                .chain(s.args.iter())
                .filter(|token| shares(token))
                .count()
        })
}

/// Whether the rule names this command as one of its subjects.
///
/// `head` is where a rule says what it is about: a rule that already names the
/// command was evaded by a spelling, and one that does not is being asked to
/// take on a new subject.
///
/// `args.0` counts as part of the name wherever a block constrains it. A
/// wrapper carries its subject in the subcommand — `fff-over-grep` is about
/// `git grep`, not about `git` — and reading the head alone files a `git diff`
/// as a rule evaded when the rule was never pointed at it.
///
/// A rule that names no head at all makes no claim to contradict.
pub fn knows_command(spec: &RuleSpec, segment: &shell::Segment) -> bool {
    let mut named = false;
    for block in &spec.blocks {
        let Some(heads) = block
            .conditions
            .get("head")
            .and_then(|predicate| predicate.any_of.as_ref())
        else {
            continue;
        };
        named = true;
        if !heads.iter().any(|head| head == &segment.head) {
            continue;
        }
        let subcommand = block
            .conditions
            .get("args.0")
            .and_then(|predicate| predicate.any_of.as_ref());
        let owned = match (subcommand, segment.args.first()) {
            (None, _) => true,
            (Some(wanted), Some(actual)) => wanted.iter().any(|value| value == actual),
            (Some(_), None) => false,
        };
        if owned {
            return true;
        }
    }
    !named
}

/// What the rule names in the same breath as this command, when it does not own
/// it — `git grep` against a `git diff`. `None` when the rule does not name the
/// command at all.
pub fn names_instead(spec: &RuleSpec, segment: &shell::Segment) -> Option<String> {
    spec.blocks.iter().find_map(|block| {
        let heads = block
            .conditions
            .get("head")
            .and_then(|predicate| predicate.any_of.as_ref())?;
        if !heads.iter().any(|head| head == &segment.head) {
            return None;
        }
        let subcommand = block
            .conditions
            .get("args.0")
            .and_then(|predicate| predicate.any_of.as_ref())?;
        Some(format!("{} {}", segment.head, subcommand.join("|")))
    })
}

/// The one shape a log entry can establish: this command, in this pipeline
/// position, anywhere in the line.
fn segment_block(head: &str, pipeline_start: bool) -> MatchBlock {
    let mut conditions = BTreeMap::new();
    conditions.insert(
        "head".to_string(),
        Predicate {
            any_of: Some(vec![head.to_string()]),
            ..Predicate::default()
        },
    );
    if pipeline_start {
        conditions.insert(
            "pipeline_start".to_string(),
            Predicate {
                is: Some(true),
                ..Predicate::default()
            },
        );
    }
    MatchBlock {
        any: Some("parsed.segments".to_string()),
        all: None,
        conditions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts_s: u64, outcome: &str, session: &str, command: &str) -> Entry {
        Entry {
            ts_ms: ts_s * 1000,
            outcome: outcome.into(),
            rules: Vec::new(),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": command }),
            session_id: Some(session.into()),
            cwd: None,
        }
    }

    // The documented escape in `edit-over-python`: `-c` is legal so a model
    // refused the heredoc can write the same program on one line.
    #[test]
    fn an_escape_is_a_deny_and_the_rephrase_that_followed_it() {
        let log = [
            entry(100, "deny", "s1", "python3 - <<'PY'\nedit(src/x.rs)\nPY"),
            entry(108, "allow", "s1", "python3 -c \"edit('src/x.rs')\""),
        ];
        let found = escapes(&log);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].gap_s, 8);
        assert!(found[0].allowed.contains("-c"));
    }

    #[test]
    fn unrelated_work_after_a_deny_is_not_an_escape() {
        // Shares only the `cd` and its path, which everything in a session does.
        let same_directory = [
            entry(100, "deny", "s1", "cd /repo && rg -n foo tests/"),
            entry(140, "allow", "s1", "cd /repo && cargo build"),
        ];
        assert!(escapes(&same_directory).is_empty());

        let too_late = [
            entry(100, "deny", "s1", "rg -n foo tests/"),
            entry(400, "allow", "s1", "rg -n foo tests/"),
        ];
        assert!(escapes(&too_late).is_empty());

        let other_session = [
            entry(100, "deny", "s1", "rg -n foo tests/"),
            entry(105, "allow", "s2", "rg -n foo tests/"),
        ];
        assert!(escapes(&other_session).is_empty());

        // An operand has to name something in particular. Two lines that both
        // say `1` or `build` are not the same attempt, and pairing on those
        // fills the report with coincidences.
        let bare_words = [
            entry(100, "deny", "s1", "find /deps -maxdepth 1 -name clap"),
            entry(110, "allow", "s1", "cargo build --release"),
        ];
        assert!(escapes(&bare_words).is_empty());
    }

    // A loop refused three times and rephrased once is one finding. Keying on
    // the deny would report the same decision three times over.
    #[test]
    fn one_call_that_got_through_is_one_escape() {
        let log = [
            entry(100, "deny", "s1", "sed -n 1,40p src/hook.rs"),
            entry(102, "deny", "s1", "sed -n 1,80p src/hook.rs"),
            entry(104, "deny", "s1", "sed -n 1,90p src/hook.rs"),
            entry(106, "allow", "s1", "nl src/hook.rs"),
        ];
        let found = escapes(&log);
        assert_eq!(found.len(), 1, "{:?}", found.len());
        assert_eq!(found[0].allowed, "nl src/hook.rs");
        assert_eq!(found[0].gap_s, 6, "the earliest deny dates the pair");
    }

    // A different command reaching the same file is the shape the pager rule
    // keeps missing, and the operand is the only thing the two spellings share.
    #[test]
    fn a_shared_operand_pairs_two_different_commands() {
        let log = [
            entry(100, "deny", "s1", "sed -n '1,80p' src/hook.rs"),
            entry(102, "allow", "s1", "nl src/hook.rs"),
        ];
        assert_eq!(escapes(&log).len(), 1);
    }

    // A draft that does not parse, or does not catch the call it was drafted
    // from, is worse than no draft: it is a paste that fails at the next
    // `validate` for a reason the reader did not introduce.
    fn pasted(draft: &Draft) -> Rule {
        let text = crate::config::to_toml(&draft.spec);
        let file: crate::config::ConfigFile =
            toml::from_str(&text).unwrap_or_else(|e| panic!("draft does not parse: {e}\n{text}"));
        Rule::compile(file.rules.into_iter().next().expect("one rule")).expect("draft compiles")
    }

    #[test]
    fn a_drafted_rule_parses_and_catches_the_call_it_came_from() {
        let log = [entry(100, "allow", "s1", "psql -h prod -c 'select 1'")];
        let shape = &shapes(&log)[0];
        let draft = draft_rule(shape);

        assert_eq!(draft.spec.test.fires, vec!["psql -h prod -c 'select 1'"]);
        assert!(pasted(&draft).fires_on(&shape.example, None));
    }

    // The difference between a rule with a hole in it and a rule that worked.
    // `python3 -c` after a denied `python3 -` is the same subject spelled
    // around; `task ts:security` after a denied `grep` is a different subject,
    // and teaching a rule about search tools to deny `task` fixes nothing.
    #[test]
    fn a_rule_is_only_evaded_by_a_command_it_names() {
        let file: crate::config::ConfigFile =
            toml::from_str(include_str!("builtin.toml")).expect("built-ins");
        let rule = |name: &str| {
            file.rules
                .iter()
                .find(|rule| rule.name == name)
                .expect("a built-in")
                .clone()
        };

        let segment = |command: &str| shell::lex(command).into_iter().next().expect("a segment");

        assert!(knows_command(
            &rule("edit-over-python"),
            &segment("python3 -c 'x'")
        ));
        assert!(!knows_command(&rule("fff-over-grep"), &segment("task x")));
        // A wrapper carries its subject in the subcommand: the rule is pointed
        // at `git grep`, so a `git diff` is as unrelated to it as `task` is.
        assert!(knows_command(
            &rule("fff-over-grep"),
            &segment("git grep foo")
        ));
        assert!(!knows_command(
            &rule("fff-over-grep"),
            &segment("git diff --stat")
        ));
        assert_eq!(
            names_instead(&rule("fff-over-grep"), &segment("git diff --stat")),
            Some("git grep".to_string())
        );
        // The rephrase is what gets asked about, not the whole line.
        let escape = Escape {
            denied: "grep -n ts:security Taskfile.yml".into(),
            rules: vec!["fff-over-grep".into()],
            allowed: "task ts:security 2>&1 | tail -30".into(),
            gap_s: 43,
            shared: "ts:security".into(),
            cwd: None,
        };
        assert_eq!(rephrase(&escape).expect("a segment").1.head, "task");
    }

    #[test]
    fn a_drafted_extension_keeps_the_rule_it_extends() {
        let file: crate::config::ConfigFile =
            toml::from_str(include_str!("builtin.toml")).expect("built-ins");
        let spec = file
            .rules
            .into_iter()
            .find(|rule| rule.name == "edit-over-python")
            .expect("the python rule");
        let escape = Escape {
            denied: "python3 - <<'PY'".into(),
            rules: vec![spec.name.clone()],
            // The rephrase is the second segment; a draft built from the first
            // would name `cargo` and catch nothing.
            allowed: "cargo build && python3 -c \"edit('src/x.rs')\"".into(),
            gap_s: 8,
            shared: "python3".into(),
            cwd: None,
        };

        let draft = draft_extension(&spec, &escape).expect("a draft");
        assert_eq!(draft.spec.blocks.len(), spec.blocks.len() + 1);
        let rule = pasted(&draft);
        assert!(rule.fires_on(&escape.allowed, None), "closes the escape");
        for still in &spec.test.fires {
            assert!(rule.fires_on(still, None), "still catches {still}");
        }
    }

    #[test]
    fn shapes_count_the_head_that_led_the_pipeline() {
        let log = [
            entry(100, "allow", "s1", "rg -n foo src"),
            entry(101, "allow", "s1", "rg -n bar src"),
            entry(102, "allow", "s1", "gh pr list | rg foo"),
            entry(103, "deny", "s1", "rg -n baz src"),
        ];
        let counted = shapes(&log);
        assert_eq!(counted[0].head, "rg");
        assert_eq!(counted[0].count, 2, "the denied call is not a shape");
        assert_eq!(counted[1].head, "gh", "a pipe does not make rg the head");
    }
}

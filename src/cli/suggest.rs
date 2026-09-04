// What the log says is missing, and the TOML that would close it.
//
// The findings here are evidence rather than answers. A pair of log lines is a
// guess about intent — one call refused, another that got through — and the
// report's job is to show the reader enough to throw the guess out: what paired
// the two, which condition held the rule open, and whether the rule ever named
// the command that ran at all.
//
// What carries a verdict is the sorting. A pair the live rules now answer is
// finished, a pair the rule declares in its own `ignores` is deliberate, a pair
// whose denying rule never heard of the command is a question, and what is left
// is the edit worth making — one line per rule and condition, because that is
// the unit an edit is made in. Five pairs escaping one rule through one
// condition are one thing to fix, not five findings.

use super::ink::{clip, row, Ink};
use crate::{config, replay, rules, shell};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::path::Path;

pub fn suggest_cmd(
    since: Option<u64>,
    apply: bool,
    draft: Option<String>,
    list_all: bool,
) -> Result<i32> {
    let entries = super::history(since)?;
    let ink = Ink::new();
    let all = replay::escapes(&entries);
    let shapes = replay::shapes(&entries);

    // Weighing a pair takes the rule that denied, not just the two log lines.
    let ruleset = config::load(&std::env::current_dir()?)?;

    let mut closed: Vec<&replay::Escape> = Vec::new();
    let mut weak: Vec<&replay::Escape> = Vec::new();
    let mut design: Vec<&replay::Escape> = Vec::new();
    let mut open: Vec<(Target, &replay::Escape)> = Vec::new();
    for escape in &all {
        match sort(escape, &ruleset) {
            Verdict::Closed => closed.push(escape),
            Verdict::Weak => weak.push(escape),
            Verdict::Design => design.push(escape),
            Verdict::Fix(target) => open.push((target, escape)),
        }
    }
    let fixes = group(open);

    // Answered from the same sorting the report prints, so the command a fix
    // line names lands on the pair that line is about.
    if let Some(name) = draft {
        return draft_cmd(&name, &fixes, &all, &shapes, &ruleset);
    }
    if apply {
        return apply_cmd(&fixes, &ruleset, &ink);
    }

    if !fixes.is_empty() {
        row(
            &ink,
            "fix",
            &ink.dim("a rule refused a call, then let the same command through"),
        );
        row(
            &ink,
            " ",
            &ink.dim("--apply records them as escapes their rules allow"),
        );
    }
    for (target, escapes) in &fixes {
        row(&ink, "fix", &headline(target, escapes.len(), &ink));
        // Evidence under the verdict rather than instead of it: the condition
        // is the same for every pair in the group, and what differs is the two
        // calls, which are the only part a reader can judge the pairing on.
        let shown = match list_all {
            true => escapes.len(),
            false => 3,
        };
        for escape in escapes.iter().take(shown) {
            row(&ink, "  denied", &ink.red(&clip(&escape.denied)));
            row(
                &ink,
                "  ran",
                &format!(
                    "{}  {}",
                    ink.green(&clip(&escape.allowed)),
                    ink.dim(&format!("+{}s", escape.gap_s))
                ),
            );
            // The pairing is a guess from one shared token. Naming it is what
            // lets a reader throw out the coincidences instead of trusting all
            // of them.
            row(
                &ink,
                "  paired",
                &ink.dim(&format!("both mention {}", escape.shared)),
            );
        }
        if escapes.len() > shown {
            row(
                &ink,
                "  ",
                &ink.dim(&format!(
                    "{} more like it (--all shows them)",
                    escapes.len() - shown
                )),
            );
        }
    }

    if !closed.is_empty() {
        row(
            &ink,
            "closed",
            &ink.dim(&format!(
                "{} {} the rules now answer, from edits already made",
                closed.len(),
                plural(closed.len())
            )),
        );
    }
    if !design.is_empty() {
        row(
            &ink,
            "design",
            &ink.dim(&format!(
                "{} {} the rule declares in its own `ignores`",
                design.len(),
                plural(design.len())
            )),
        );
    }
    if !weak.is_empty() {
        row(
            &ink,
            "weak",
            &ink.dim(&format!(
                "{} {} where the denying rule knows nothing about what ran{}",
                weak.len(),
                plural(weak.len()),
                match list_all {
                    true => "",
                    false => " (--all lists them)",
                }
            )),
        );
    }
    // A weak pair has no verdict to group under, so it keeps the per-pair form.
    if list_all {
        for escape in weak.iter().take(40) {
            row(&ink, "weak", &ink.bold(&escape.rules.join(", ")));
            row(&ink, "  denied", &ink.red(&clip(&escape.denied)));
            row(
                &ink,
                "  ran",
                &format!(
                    "{}  {}",
                    ink.green(&clip(&escape.allowed)),
                    ink.dim(&format!("+{}s", escape.gap_s))
                ),
            );
            row(&ink, "  signal", &why_weak(escape, &ruleset, &ink));
        }
    }
    let reported = !fixes.is_empty() || !closed.is_empty() || !weak.is_empty();
    if reported && !shapes.is_empty() {
        println!();
    }

    if !shapes.is_empty() {
        row(
            &ink,
            "shapes",
            &ink.dim("allowed calls nothing caught, by the command that led them"),
        );
    }
    for shape in shapes.iter().take(15) {
        row(
            &ink,
            "shape",
            &format!(
                "{:<12} {:>5}  {}",
                ink.bold(&shape.head),
                shape.count,
                ink.dim(&clip(&shape.example))
            ),
        );
    }

    row(&ink, "", "");
    row(
        &ink,
        "ok",
        &format!(
            "{}, {} closed, {} by design, {} weak, {} uncaught shapes",
            ink.bold(&format!(
                "{} {}",
                fixes.len(),
                match fixes.len() {
                    1 => "fix",
                    _ => "fixes",
                }
            )),
            closed.len(),
            design.len(),
            weak.len(),
            shapes.len()
        ),
    );
    // Every fix line already carries its own draft command, so this one is for
    // the case where the only thing left to look at is a shape.
    if fixes.is_empty() {
        if let Some(shape) = shapes.first() {
            row(
                &ink,
                "draft",
                &ink.dim(&format!(
                    "steer suggest --draft {}  starts a rule for that shape",
                    shape.head
                )),
            );
        }
    }
    Ok(0)
}

fn plural(count: usize) -> &'static str {
    match count {
        1 => "pair",
        _ => "pairs",
    }
}

/// The rule an escape is a finding about, and the conditions that held it open.
struct Target {
    rule: String,
    condition: String,
}

/// Open escapes gathered under the edit that would close them.
///
/// Ordered by how many pairs each has behind it, since the count is the only
/// measure the log offers of how much a hole is actually costing.
fn group(escapes: Vec<(Target, &replay::Escape)>) -> Vec<(Target, Vec<&replay::Escape>)> {
    let mut groups: Vec<(Target, Vec<&replay::Escape>)> = Vec::new();
    for (target, escape) in escapes {
        match groups
            .iter_mut()
            .find(|(at, _)| at.rule == target.rule && at.condition == target.condition)
        {
            Some((_, found)) => found.push(escape),
            None => groups.push((target, vec![escape])),
        }
    }
    groups.sort_by_key(|(_, escapes)| std::cmp::Reverse(escapes.len()));
    groups
}

impl Target {
    /// How a fix is addressed on the command line. One rule can be open through
    /// two conditions, and those are two different edits, so the rule name alone
    /// does not say which.
    fn address(&self) -> String {
        format!("{}:{}", self.rule, self.condition)
    }
}

/// Which of the four things a pair is.
enum Verdict {
    Closed,
    Weak,
    Design,
    Fix(Target),
}

/// The bucket a pair belongs in, worked out once.
///
/// The order is the whole of the judgement. Closed comes off first: a pair the
/// live rules now answer is finished work whichever bucket it would otherwise
/// land in, and filing it as a finding asks the reader about an edit they have
/// already made. Then whether the rule that denied ever named the command that
/// ran — without that the pairing is a coincidence, and a question rather than
/// a finding. Then what the rule says about itself, since a command it declares
/// in `ignores` got through because the rule is written to let it. What is left
/// is a hole, named by the rule and the condition an edit would go to.
fn sort(escape: &replay::Escape, ruleset: &[rules::Rule]) -> Verdict {
    if replay::closed(escape, ruleset) {
        return Verdict::Closed;
    }
    let cwd = replay::cwd(escape);
    let Some((rule, held_open)) = knows(escape, ruleset, cwd.as_deref()) else {
        return Verdict::Weak;
    };
    match declared(rule, &held_open, cwd.as_deref()) {
        true => Verdict::Design,
        false => Verdict::Fix(Target {
            rule: rule.spec.name.clone(),
            condition: held_open.1,
        }),
    }
}

/// The rule that denied and named the command that ran next, with the block and
/// conditions that held it open — the line between a pair worth reading and a
/// coincidence.
///
/// Both halves have to come from the same rule and the same segment. A rule
/// pointed at `git grep` says nothing about the `git diff` that ran, and naming
/// a condition from a rule that was never about this command would dress a
/// coincidence as a hole.
fn knows<'a>(
    escape: &replay::Escape,
    ruleset: &'a [rules::Rule],
    cwd: Option<&Path>,
) -> Option<(&'a rules::Rule, (Option<usize>, String))> {
    let (element, segment) = replay::rephrase(escape)?;
    let rule = ruleset
        .iter()
        .filter(|rule| escape.rules.contains(&rule.spec.name))
        .find(|rule| replay::knows_command(&rule.spec, &segment))?;
    Some((rule, miss(rule, &escape.allowed, cwd, element)))
}

/// Whether the rule says, in its own examples, that it means to let this
/// through.
///
/// A rule's `ignores` are the commands it must not fire on. They are written by
/// hand and run by `validate`, which makes them the one place an intentional
/// escape is both stated and enforced — a prose comment above the rule is
/// neither. An ignore that misses the same block on the same condition is that
/// statement, about this escape.
///
/// The block rather than the command, because every head in one block shares
/// every other condition: `rg` outside the tree and `grep` outside the tree are
/// one escape of one block, and declaring it once is the honest amount of
/// writing.
fn declared(rule: &rules::Rule, held_open: &(Option<usize>, String), cwd: Option<&Path>) -> bool {
    rule.spec.test.ignores.iter().any(|ignore| {
        (0..shell::lex(ignore).len()).any(|at| &miss(rule, ignore, cwd, at) == held_open)
    })
}

/// The command is the point of the line, so it is not the dimmest thing on it.
fn headline(target: &Target, pairs: usize, ink: &Ink) -> String {
    format!(
        "{:<24} {:<16} {:>2} {:<6} {}",
        ink.bold(&target.rule),
        ink.yellow(&target.condition),
        pairs,
        plural(pairs),
        ink.cyan(&format!("steer suggest --draft {}", target.address()))
    )
}

/// Which of the two things a weak pair is: a rule pointed at something else, or
/// a rule that never named this command at all.
///
/// A rule refuses on the command it names. When the call that followed leads
/// with something else, the model went and did a different thing — which is what
/// following the guidance looks like from the log, and is indistinguishable from
/// evasion by timing alone.
fn why_weak(escape: &replay::Escape, ruleset: &[rules::Rule], ink: &Ink) -> String {
    let Some((_, segment)) = replay::rephrase(escape) else {
        return ink.dim("nothing in the second call to compare");
    };
    let denying: Vec<&rules::Rule> = ruleset
        .iter()
        .filter(|rule| escape.rules.contains(&rule.spec.name))
        .collect();
    if denying.is_empty() {
        return ink.dim("the rule that denied is no longer in the ruleset");
    }
    // A rule pointed at `git grep` says as little about `git diff` as it does
    // about `task`, and saying which it is about is more use than saying the
    // command is unfamiliar.
    let instead = denying
        .iter()
        .find_map(|rule| replay::names_instead(&rule.spec, &segment));
    match instead {
        Some(subject) => ink.dim(&format!(
            "the rule is about `{subject}`, and this is `{} {}`",
            segment.head,
            segment.args.first().map_or("", String::as_str)
        )),
        None => ink.dim(&format!(
            "the rule says nothing about `{}` — as likely the model taking the guidance",
            segment.head
        )),
    }
}

/// Which block a command came closest to firing, and the conditions of it that
/// did not hold — named by path alone: `in_workspace`, not
/// `in_workspace=false`. The value one landed on can be an entire heredoc, and
/// the path is what an edit is made against anyway.
///
/// The block travels with the conditions because a condition means nothing
/// without one. Two rules can both miss on `args` and be about different
/// things, and so can two blocks of the same rule.
///
/// The engine's own pick is the nearest binding anywhere in the line, which on
/// `git diff … | grep …` is a different segment than the one that rephrased the
/// denied call. Reporting that one would pair a claim about `grep` with a
/// condition about `git`, and both halves being true does not make the sentence
/// true.
fn miss(
    rule: &rules::Rule,
    command: &str,
    cwd: Option<&Path>,
    element: usize,
) -> (Option<usize>, String) {
    let input = json!({ "command": command });
    let Some(trace) = rules::trace_at(
        std::slice::from_ref(rule),
        "Bash",
        &input,
        cwd,
        Some(element),
    )
    .into_iter()
    .next() else {
        return (None, "matches".to_string());
    };
    let mut paths: Vec<String> = Vec::new();
    for check in trace.checks.iter().filter(|check| !check.held) {
        if !paths.contains(&check.path) {
            paths.push(check.path.clone());
        }
    }
    match paths.is_empty() {
        // Out of reach while closed pairs are sorted out first: a rule with
        // every condition holding is a rule that fired, and a fired deny is not
        // an escape. Kept as a label rather than an assertion, since arriving
        // here would mean `trace` and `evaluate` disagree.
        true => (None, "matches".to_string()),
        false => (Some(trace.block), paths.join(", ")),
    }
}

/// Why there is nothing to draft, and the two edits that would actually serve —
/// neither of which a log can choose between.
///
/// Widening an existing block is named rather than appending a new one because
/// that is the edit that keeps the rule honest: a command added to a block it
/// belongs with inherits that block's other conditions, where an appended block
/// would carry none of them and deny far more than the rule ever did.
fn unrelated(rule: &str, subject: &str, head: &str, escape: &replay::Escape) -> String {
    format!(
        "`{rule}` says nothing about `{subject}`, so there is no block worth drafting.\n\
         \n  denied  {}\n  ran     {}\n\n\
         It refused a command it names and a different one ran next, which is as \
         likely the model taking the guidance as routing around it. Two ways \
         forward, both yours to judge:\n\
         \n  `{subject}` is another way of doing what was refused\n\
         \x20     widen the block it belongs with by hand — its `head` list, or the \
         `args.0` that pins the subcommand — so it inherits that block's other \
         conditions\n\
         \n  `{head}` wants steering on its own terms\n\
         \x20     steer suggest --draft {head}",
        clip(&escape.denied),
        clip(&escape.allowed),
    )
}

/// Every fix written into the config as an escape its rule allows.
///
/// The half of the answer a log can carry. Whether an escape was meant is a fact
/// about intent, and nothing in a pair of log lines holds it, so what gets
/// written is the claim that changes no matching. Closing one is the other half,
/// and it is a rule edit a person makes.
fn apply_cmd(
    fixes: &[(Target, Vec<&replay::Escape>)],
    live: &[rules::Rule],
    ink: &Ink,
) -> Result<i32> {
    let mut written = String::new();
    for (target, escapes) in fixes {
        let Some(rule) = live.iter().find(|rule| rule.spec.name == target.rule) else {
            continue;
        };
        let examples: Vec<String> = escapes
            .iter()
            .filter_map(|escape| replay::declaration(rule, escape))
            .collect();
        if examples.is_empty() {
            continue;
        }
        row(
            ink,
            "apply",
            &format!(
                "{:<24} {:<16} {}",
                ink.bold(&target.rule),
                ink.yellow(&target.condition),
                ink.green(&format!("{} declared", examples.len()))
            ),
        );
        // The bytes, not a rendering of them. A clipped command reads as a
        // summary of the edit and is one, which leaves the only exact account of
        // what landed inside the file it landed in.
        let block = config::amendment_toml(&target.rule, &examples);
        for line in block.lines() {
            row(ink, "  ", &ink.green(line));
        }
        written.push_str(&block);
        written.push('\n');
    }
    if written.is_empty() {
        row(ink, "ok", "nothing to apply");
        return Ok(0);
    }
    // The nearest file that already holds rules, so a repo keeps its decisions
    // and a machine without one keeps them globally.
    let cwd = std::env::current_dir()?;
    let path = config::overlay_path(&cwd)
        .or_else(config::global_path)
        .context("neither XDG_CONFIG_HOME nor HOME is set")?;
    config::append(&path, &written)?;
    row(ink, "", "");
    row(
        ink,
        "wrote",
        &format!(
            "{}  — `steer validate` holds them from here",
            ink.bold(&path.display().to_string())
        ),
    );
    Ok(0)
}

/// TOML and the comments that explain it, and nothing else, so it appends
/// straight to a config file.
///
/// The pair drafted from is the one the report named, taken from the fixes
/// rather than from the log. Reaching into the log directly takes whichever pair
/// came first in time, which is as likely to be a closed one or a weak one — and
/// then the command a fix line prints declines over a pair that line
/// deliberately did not show. Falling back to the log is still right where a
/// rule has no fix behind it, since declining with the reason is the answer
/// there.
fn draft_cmd(
    name: &str,
    fixes: &[(Target, Vec<&replay::Escape>)],
    all: &[replay::Escape],
    shapes: &[replay::Shape],
    live: &[rules::Rule],
) -> Result<i32> {
    // `fff-over-grep:pipeline_start` picks one of a rule's fixes; the bare name
    // takes the one with the most pairs behind it, which is what the report
    // leads with.
    let (name, condition) = match name.split_once(':') {
        Some((rule, condition)) => (rule, Some(condition)),
        None => (name, None),
    };
    let escaped = fixes
        .iter()
        .find(|(target, _)| {
            target.rule == name && condition.is_none_or(|want| target.condition == want)
        })
        .and_then(|(_, escapes)| escapes.first().copied())
        .or_else(|| {
            all.iter()
                .find(|escape| escape.rules.iter().any(|rule| rule == name))
        })
        .zip(live.iter().find(|rule| rule.spec.name == name));

    // Declining rather than printing a draft under a caveat: the artifact is
    // the recommendation, and the caveat would end up in the config as the only
    // trace of a doubt nobody read.
    if let Some((escape, rule)) = escaped {
        if let Some((_, segment)) = replay::rephrase(escape) {
            if !replay::knows_command(&rule.spec, &segment) {
                // The subcommand belongs in the name only where the rule pins
                // one: `git diff` against a rule about `git grep`, but plain
                // `task` against a rule that never heard of it.
                let subject = match replay::names_instead(&rule.spec, &segment) {
                    Some(_) => format!(
                        "{} {}",
                        segment.head,
                        segment.args.first().map_or("", String::as_str)
                    ),
                    None => segment.head.clone(),
                };
                bail!(unrelated(name, subject.trim(), &segment.head, escape));
            }
        }
    }

    let extension = escaped.and_then(|(escape, rule)| replay::draft_extension(&rule.spec, escape));
    // A shape draft is the fallback for a rule that has left the ruleset, or an
    // escaped command that lexed to nothing a block could bind to.
    let draft = extension.or_else(|| {
        shapes
            .iter()
            .find(|shape| shape.head == name)
            .map(replay::draft_rule)
    });

    let Some(draft) = draft else {
        bail!("nothing to draft for `{name}`: no escaped deny names that rule, and no allowed call leads with it")
    };
    let ink = Ink::new();
    let mut text = String::new();
    // Every line of a note, not every note. A note quotes a logged command and
    // a logged command can be a heredoc carrying a whole document, so one `#`
    // on the first line leaves the rest of it as bare TOML in the file this
    // gets redirected into.
    for note in &draft.notes {
        match note.is_empty() {
            true => text.push_str(&format!("{}\n", ink.dim("#"))),
            false => {
                for line in note.lines() {
                    let comment = format!("# {line}");
                    // The diff is the part of the comment block worth reading,
                    // so it is not dimmed along with the prose around it.
                    text.push_str(&match line.starts_with("+ ") {
                        true => format!("{}\n", ink.green(&comment)),
                        false => format!("{}\n", ink.dim(&comment)),
                    });
                }
            }
        }
    }
    text.push_str(&highlight(
        &config::to_toml(&draft.spec),
        &draft.added,
        &ink,
    ));
    print!("{text}");
    Ok(0)
}

/// TOML with its structure picked out and the lines the draft is responsible
/// for marked, for a terminal only — the same text is what gets redirected into
/// a config file, so the marking is colour and never a character in the margin.
fn highlight(toml: &str, added: &[usize], ink: &Ink) -> String {
    let mut out = String::new();
    let mut in_message = false;
    for (at, line) in toml.lines().enumerate() {
        let new = added.contains(&at);
        // A `"""` message is prose, and prose full of `#` and `=` would come
        // out looking like config.
        if in_message {
            in_message = line.matches("\"\"\"").count() % 2 == 0;
            out.push_str(&match new {
                true => ink.green(line),
                false => line.to_string(),
            });
            out.push('\n');
            continue;
        }
        let trimmed = line.trim_start();
        // What the draft adds outranks what the line is: the reader is looking
        // for four lines in a screenful of rule.
        let rendered = if new {
            ink.green(line)
        } else if trimmed.starts_with('[') {
            ink.bold(line)
        } else if let Some((key, value)) = line.split_once(" = ") {
            format!("{} = {value}", ink.cyan(key))
        } else {
            line.to_string()
        };
        in_message = line.matches("\"\"\"").count() % 2 == 1;
        out.push_str(&rendered);
        out.push('\n');
    }
    out
}

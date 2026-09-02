// What the log says is missing, and the TOML that would close it.
//
// The findings here are evidence rather than answers. A pair of log lines is a
// guess about intent — one call refused, another that got through — and the
// report's job is to show the reader enough to throw the guess out: what paired
// the two, which condition held the rule open, and whether the rule ever named
// the command that ran at all.

use super::ink::{clip, row, Ink};
use crate::{config, replay, rules};
use anyhow::{bail, Result};
use serde_json::json;

pub fn suggest_cmd(
    since: Option<u64>,
    draft: Option<String>,
    strong: bool,
    list_all: bool,
) -> Result<i32> {
    let entries = super::history(since)?;
    let ink = Ink::new();
    let all = replay::escapes(&entries);
    let shapes = replay::shapes(&entries);

    if let Some(name) = draft {
        return draft_cmd(&name, &all, &shapes);
    }
    // Weighing a pair takes the rule that denied, not just the two log lines.
    let ruleset = config::load(&std::env::current_dir()?)?;

    // A weak pair is a question, not a finding, and there are usually many more
    // of them than there are findings. Listing every one buries the two lines
    // worth reading, so by default they are counted rather than printed.
    let (strong_escapes, weak): (Vec<&replay::Escape>, Vec<&replay::Escape>) =
        all.iter().partition(|escape| knows(escape, &ruleset));
    let escapes: Vec<&replay::Escape> = match (strong, list_all) {
        (true, _) => strong_escapes.clone(),
        (false, true) => all.iter().collect(),
        (false, false) => strong_escapes.clone(),
    };
    let shapes: &[replay::Shape] = match strong {
        // A count of what the model reaches for is not a finding about a rule,
        // and this flag is for the ones that are.
        true => &[],
        false => &shapes,
    };

    // An escape only means something as a pair of log lines, and a shape is a
    // count with no judgement attached.
    if !escapes.is_empty() {
        row(
            &ink,
            "escapes",
            &ink.dim("a rule refused a call, and one that got through retried it"),
        );
    }
    for escape in escapes.iter().take(20) {
        row(&ink, "escape", &ink.bold(&escape.rules.join(", ")));
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
        // The pairing is a guess from one shared token. Naming it is what lets
        // a reader throw out the coincidences instead of trusting all of them.
        row(
            &ink,
            "  paired",
            &ink.dim(&format!("both mention {}", escape.shared)),
        );
        row(&ink, "  signal", &verdict(escape, &ruleset, &ink));
    }
    if !weak.is_empty() && !list_all {
        row(
            &ink,
            "weak",
            &ink.dim(&format!(
                "{} more {} where the denying rule knows nothing about what ran{}",
                weak.len(),
                match weak.len() {
                    1 => "pair",
                    _ => "pairs",
                },
                match strong {
                    true => "",
                    false => " (--all lists them)",
                }
            )),
        );
    }
    if !escapes.is_empty() || !weak.is_empty() {
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
            "{} escaped denies, {} allowed shapes",
            ink.bold(&strong_escapes.len().to_string()),
            shapes.len()
        ),
    );
    // The flag is invisible unless the report names it, and it points at the
    // first escape worth acting on — a weak one is a question, not a task.
    let strongest = escapes
        .iter()
        .filter(|escape| knows(escape, &ruleset))
        .find_map(|escape| escape.rules.first());
    if let Some(name) = strongest.or_else(|| shapes.first().map(|shape| &shape.head)) {
        row(
            &ink,
            "draft",
            &ink.dim(&format!(
                "steer suggest --draft {name}  writes the TOML for that one"
            )),
        );
    }
    Ok(0)
}

/// Whether the rule that denied names the command that ran next — the line
/// between a pair worth reading and a coincidence.
fn knows(escape: &replay::Escape, ruleset: &[rules::Rule]) -> bool {
    replay::rephrase(escape).is_some_and(|(_, segment)| {
        ruleset
            .iter()
            .filter(|rule| escape.rules.contains(&rule.spec.name))
            .any(|rule| replay::knows_command(&rule.spec, &segment))
    })
}

/// Which of the two things a pair is: a rule evaded, or a rule obeyed.
///
/// A rule refuses on the command it names. When the call that followed leads
/// with that same command, the rule was routed around by a spelling and has a
/// hole. When it leads with something else, the model went and did a different
/// thing — which is what following the guidance looks like from the log, and is
/// indistinguishable from evasion by timing alone.
fn verdict(escape: &replay::Escape, ruleset: &[rules::Rule], ink: &Ink) -> String {
    let Some((element, segment)) = replay::rephrase(escape) else {
        return ink.dim("nothing in the second call to compare");
    };
    let denying: Vec<&rules::Rule> = ruleset
        .iter()
        .filter(|rule| escape.rules.contains(&rule.spec.name))
        .collect();
    if denying.is_empty() {
        return ink.dim("the rule that denied is no longer in the ruleset");
    }
    let Some(rule) = denying
        .iter()
        .find(|rule| replay::knows_command(&rule.spec, &segment))
    else {
        // A rule pointed at `git grep` says as little about `git diff` as it
        // does about `task`, and saying which it is about is more use than
        // saying the command is unfamiliar.
        let instead = denying
            .iter()
            .find_map(|rule| replay::names_instead(&rule.spec, &segment));
        return match instead {
            Some(subject) => ink.dim(&format!(
                "weak: the rule is about `{subject}`, and this is `{} {}`",
                segment.head,
                segment.args.first().map_or("", String::as_str)
            )),
            None => ink.dim(&format!(
                "weak: the rule says nothing about `{}` — as likely the model taking the guidance",
                segment.head
            )),
        };
    };
    // Naming the condition rather than calling it a hole. Every one of these
    // is a rule that knows the command and let it through anyway, and the
    // condition says which: `in_workspace` and `pipeline_start` are usually the
    // escape the rule documents, an argument is usually a spelling it misses.
    let held_open = missed(&rule.spec.name, escape, element, ruleset);
    match held_open.is_empty() {
        true => ink.yellow(&format!(
            "the rule matches `{}` and let it through",
            segment.head
        )),
        false => ink.yellow(&format!(
            "the rule knows `{}`; {} is what let it through",
            segment.head,
            held_open.join(", ")
        )),
    }
}

/// The conditions that did not hold on the segment the report is about.
///
/// The engine's own pick is the nearest binding anywhere in the line, which on
/// `git diff … | grep …` is a different segment than the one that rephrased the
/// denied call. Reporting that one would pair a claim about `grep` with a
/// condition about `git`, and both halves being true does not make the sentence
/// true.
fn missed(
    rule: &str,
    escape: &replay::Escape,
    element: usize,
    ruleset: &[rules::Rule],
) -> Vec<String> {
    let cwd = escape
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());
    let input = json!({ "command": escape.allowed });
    rules::trace_at(ruleset, "Bash", &input, cwd.as_deref(), Some(element))
        .into_iter()
        .find(|trace| trace.rule == rule)
        .map(|trace| {
            trace
                .checks
                .iter()
                .filter(|check| !check.held)
                .map(|check| format!("{}={}", check.path, check.actual))
                .collect()
        })
        .unwrap_or_default()
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

/// TOML and the comments that explain it, and nothing else, so it appends
/// straight to a config file.
fn draft_cmd(name: &str, escapes: &[replay::Escape], shapes: &[replay::Shape]) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let live = config::load(&cwd)?;

    let escaped = escapes
        .iter()
        .find(|escape| escape.rules.iter().any(|rule| rule == name))
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
    let mut text = String::new();
    for note in &draft.notes {
        match note.is_empty() {
            true => text.push_str("#\n"),
            false => text.push_str(&format!("# {note}\n")),
        }
    }
    text.push_str(&config::to_toml(&draft.spec));
    print!("{}", highlight(&text, &Ink::new()));
    Ok(0)
}

/// TOML with its structure picked out, for a terminal only — the same text is
/// what gets redirected into a config file, and escapes must not survive that.
fn highlight(toml: &str, ink: &Ink) -> String {
    let mut out = String::new();
    let mut in_message = false;
    for line in toml.lines() {
        // A `"""` message is prose, and prose full of `#` and `=` would come
        // out looking like config.
        if in_message {
            in_message = line.matches("\"\"\"").count() % 2 == 0;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let trimmed = line.trim_start();
        let rendered = if trimmed.starts_with('#') {
            ink.dim(line)
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

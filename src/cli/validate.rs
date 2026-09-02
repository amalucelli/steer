// The effective ruleset, printed source by source rather than collapsed.
//
// A rule count cannot answer the question a stack of three sources raises:
// which definition of a name is the live one. So the layers print as declared,
// and each rule carries what the stack did to it — replaced, disabled, or held
// back by a binary that is not there.

use super::ink::{row, Ink};
use super::render::{headline, print_rule};
use crate::{config, rules};
use anyhow::Result;
use std::path::Path;

pub fn validate() -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let report = config::inspect(&cwd)?;
    let ink = Ink::new();
    let active = print_layers(&report, &cwd, &ink);

    println!();
    for problem in &report.problems {
        row(
            &ink,
            "problem",
            &format!("{}: {}", ink.red(&problem.location), problem.detail),
        );
    }
    if report.problems.is_empty() {
        row(&ink, "ok", &ink.green(&format!("{active} rules")));
        return Ok(0);
    }
    Ok(1)
}

/// Every source, the rules it declares, and what each of those tests: which
/// definition of a name is the live one, and what has to hold for it to fire.
/// Returns how many rules survive the stack.
fn print_layers(report: &config::Report, cwd: &Path, ink: &Ink) -> usize {
    let mut active = 0;
    for (index, layer) in report.layers.iter().enumerate() {
        if index > 0 {
            println!();
        }
        row(ink, "source", &ink.bold(&layer.label));
        let Some(rules) = &layer.rules else {
            row(ink, "", &ink.red("unparsed"));
            continue;
        };
        for name in &layer.disable {
            row(ink, "disable", name);
        }
        if rules.is_empty() && layer.disable.is_empty() {
            row(ink, "", "no rules");
        }
        let width = rules
            .iter()
            .map(|spec| spec.name.chars().count())
            .max()
            .unwrap_or(0);

        for (position, spec) in rules.iter().enumerate() {
            let name = ink.bold(&format!("{:<width$}", spec.name));
            row(ink, "rule", &format!("{name}  {}", headline(spec, ink)));
            match state(report, index, position, spec) {
                State::Live => active += 1,
                State::Held(note) => {
                    active += 1;
                    row(ink, "", &ink.yellow(&note));
                }
                State::Dropped(note) => row(ink, "", &ink.yellow(&note)),
            }
            if !spec.description.is_empty() {
                row(ink, "", &spec.description);
            }
            print_rule(spec, cwd, ink);
        }
    }
    active
}

/// What the stack left of a declared rule.
enum State {
    Live,
    /// Loaded, but the engine holds it back where it would have fired.
    Held(String),
    /// Not in the effective ruleset at all.
    Dropped(String),
}

fn state(report: &config::Report, layer: usize, position: usize, spec: &rules::RuleSpec) -> State {
    let later = report
        .layers
        .iter()
        .enumerate()
        .flat_map(|(i, l)| {
            l.rules
                .iter()
                .flatten()
                .enumerate()
                .map(move |(j, r)| (i, j, r))
        })
        .find(|(i, j, r)| (*i, *j) > (layer, position) && r.name == spec.name);
    if let Some((i, _, _)) = later {
        return State::Dropped(format!("replaced by {}", report.layers[i].label));
    }
    if let Some(source) = report
        .layers
        .iter()
        .find(|l| l.disable.contains(&spec.name))
    {
        return State::Dropped(format!("disabled by {}", source.label));
    }
    if let rules::Action::Rewrite {
        replace_head: Some(head),
        ..
    } = &spec.action
    {
        if !rules::on_path(head) {
            return State::Held(format!("held: `{head}` is not on PATH"));
        }
    }
    State::Live
}

// The report behind a decision, for a reader rather than for the harness.
//
// Diagnostics only — `evaluate` answers with a decision and never pays for
// this. The two run the same predicate evaluation on purpose, so a report can
// never disagree with the decision it is reporting on.
//
// A rule that missed missed on one binding, and picking which one to report is
// most of the work here: `all` fails on its weakest element and `any` succeeds
// on its strongest, but an element the rule is actually about outranks either.

use super::compile::{resolve, Binding, CompiledBlock, Rule};
use super::document::document;
use serde_json::Value;
use std::path::Path;

/// One operator of one condition, as it landed against a single binding.
pub struct Checked {
    pub path: String,
    pub op: &'static str,
    pub held: bool,
    /// What the document had at that path, or `absent`.
    pub actual: String,
}

/// The closest a rule came to firing: the block, and the element its conditions
/// were bound to, that account for the outcome.
pub struct Trace {
    pub rule: String,
    pub block: usize,
    /// The bound element named the way the config addresses it.
    pub binding: String,
    pub checks: Vec<Checked>,
}

impl Trace {
    pub fn held(&self) -> usize {
        self.checks.iter().filter(|check| check.held).count()
    }

    pub fn missing(&self) -> usize {
        self.checks.len() - self.held()
    }

    /// Whether the rule is about this command at all. `head` is the one path
    /// that carries a rule's identity rather than a qualifier: a rule wanting
    /// `find` is not a near miss on a `git` command, however many of its other
    /// conditions happen to hold. A convention of the report, not of the engine
    /// — matching treats every path alike.
    pub fn on_topic(&self) -> bool {
        self.checks
            .iter()
            .filter(|check| check.path == "head")
            .all(|check| check.held)
    }
}

/// Why each rule did or did not fire. Diagnostics only: `evaluate` answers with
/// a decision and never pays for this.
pub fn trace(
    rules: &[Rule],
    tool_name: &str,
    tool_input: &Value,
    cwd: Option<&Path>,
) -> Vec<Trace> {
    trace_at(rules, tool_name, tool_input, cwd, None)
}

/// The same report, narrowed to one element of the bound array.
///
/// A caller reading a compound line usually has its own opinion about which
/// segment the answer should be about, and the engine's pick — the nearest
/// binding anywhere in the line — is not always that one.
pub fn trace_at(
    rules: &[Rule],
    tool_name: &str,
    tool_input: &Value,
    cwd: Option<&Path>,
    element: Option<usize>,
) -> Vec<Trace> {
    let (_, doc) = document(tool_name, tool_input, cwd);

    let mut traces = Vec::new();
    for rule in rules {
        // A rule gated on another tool has no bearing on this call, so it stays
        // out of the report rather than appearing as a rule that missed.
        if !rule.applies_to(&doc) {
            continue;
        }
        let mut best: Option<Trace> = None;
        for (index, block) in rule.blocks.iter().enumerate() {
            let bindings: Vec<(String, Option<usize>, &Value)> = match &block.binding {
                Binding::Root => vec![("tool input".to_string(), None, &doc)],
                Binding::Any(path) | Binding::All(path) => {
                    let spec = &rule.spec.blocks[index];
                    let name = spec.any.as_ref().or(spec.all.as_ref());
                    match resolve(&doc, path) {
                        Some(Value::Array(items)) => items
                            .iter()
                            .enumerate()
                            .map(|(i, item)| {
                                (
                                    format!("{}[{i}]", name.map_or("", String::as_str)),
                                    Some(i),
                                    item,
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    }
                }
            };
            for (name, at, value) in bindings {
                if element.is_some() && at != element {
                    continue;
                }
                let candidate = Trace {
                    rule: rule.spec.name.clone(),
                    block: index,
                    binding: name,
                    checks: checked(block, value),
                };
                // `all` fails on its weakest element, `any` succeeds on its
                // strongest, so each reports the element that decided it — but
                // an element the rule is actually about outranks either.
                let decisive = match (&best, &block.binding) {
                    (None, _) => true,
                    (Some(best), _) if candidate.on_topic() != best.on_topic() => {
                        candidate.on_topic()
                    }
                    (Some(best), Binding::All(_)) => candidate.held() < best.held(),
                    (Some(best), _) => candidate.held() > best.held(),
                };
                if decisive {
                    best = Some(candidate);
                }
            }
        }
        traces.extend(best);
    }
    traces
}

fn checked(block: &CompiledBlock, binding: &Value) -> Vec<Checked> {
    let mut checks = Vec::new();
    for (path, parts, predicate) in &block.conditions {
        let value = resolve(binding, parts);
        let actual = value.map_or_else(|| "absent".to_string(), Value::to_string);
        for (op, held) in predicate.checks(value) {
            checks.push(Checked {
                path: path.clone(),
                op,
                held,
                actual: actual.clone(),
            });
        }
    }
    checks
}

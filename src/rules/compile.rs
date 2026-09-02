// A spec with its globs and regexes turned into something that can answer a
// question, plus the checks that reject a rule nobody could read.
//
// Compilation is where a rule is judged as a whole. `deny_unknown_fields`
// catches a typo; what it cannot catch is a rule that parses and means nothing —
// two gates that can disagree, a rewrite that edits nothing, a condition with no
// operator. Those fail here, once, at load.
//
// A `[[rules.match]]` block's conditions are AND'd against a single binding, and
// the blocks are OR'd. That matters for correlation: a block bound with
// `any = "parsed.segments"` asks whether *one* segment satisfies every
// condition, so `cd /repo && grep foo` cannot pass by having one segment supply
// the head and another supply the pipeline position.

use super::document::document;
use super::rewrite::splice;
use super::spec::{Action, Predicate, RuleSpec};
use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde_json::{json, Value};
use std::path::Path;

/// A rule with its globs and regexes compiled once at load.
pub struct Rule {
    pub spec: RuleSpec,
    pub(super) blocks: Vec<CompiledBlock>,
}

pub(super) struct CompiledBlock {
    pub(super) binding: Binding,
    /// The path is kept as written as well as parsed, so a report can name the
    /// condition the way the config spells it.
    pub(super) conditions: Vec<(String, Vec<PathPart>, CompiledPredicate)>,
}

pub(super) enum Binding {
    Root,
    Any(Vec<PathPart>),
    All(Vec<PathPart>),
}

#[derive(Default)]
pub(super) struct CompiledPredicate {
    any_of: Option<Vec<String>>,
    none_of: Option<Vec<String>>,
    glob: Option<GlobSet>,
    none_glob: Option<GlobSet>,
    matches: Option<Regex>,
    is: Option<bool>,
}

pub(super) enum PathPart {
    Key(String),
    Index(usize),
}

fn parse_path(path: &str) -> Vec<PathPart> {
    path.split('.')
        .filter(|p| !p.is_empty())
        .map(|p| match p.parse::<usize>() {
            Ok(n) => PathPart::Index(n),
            Err(_) => PathPart::Key(p.to_string()),
        })
        .collect()
}

pub(super) fn resolve<'a>(value: &'a Value, path: &[PathPart]) -> Option<&'a Value> {
    let mut cur = value;
    for part in path {
        cur = match part {
            PathPart::Key(k) => cur.get(k)?,
            PathPart::Index(i) => cur.get(i)?,
        };
    }
    Some(cur)
}

fn build_globs(patterns: &[String], rule: &str, path: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern)
                .with_context(|| format!("rule `{rule}`: bad glob `{pattern}` at `{path}`"))?,
        );
    }
    builder.build().map_err(Into::into)
}

impl Rule {
    pub fn compile(spec: RuleSpec) -> Result<Rule> {
        if spec.name.trim().is_empty() {
            bail!("a rule is missing a name");
        }
        if spec.blocks.is_empty() {
            bail!("rule `{}` has no [[rules.match]] block", spec.name);
        }
        // Two gates on one rule can disagree, and a reader has no way to tell
        // which won.
        if spec.agents.is_some() && spec.action.message().is_per_agent() {
            bail!(
                "rule `{}`: a per-harness message already gates this rule; drop `agents`",
                spec.name
            );
        }
        if let Action::Rewrite {
            replace_head,
            drop_args,
            add_args,
            ..
        } = &spec.action
        {
            if replace_head.is_none() && drop_args.is_empty() && add_args.is_empty() {
                bail!(
                    "rule `{}`: a rewrite edits nothing without replace_head, drop_args, or add_args",
                    spec.name
                );
            }
        }
        let mut blocks = Vec::with_capacity(spec.blocks.len());
        for block in &spec.blocks {
            let binding = match (&block.any, &block.all) {
                (Some(_), Some(_)) => {
                    bail!("rule `{}`: a match block sets both any and all", spec.name)
                }
                (Some(p), None) => Binding::Any(parse_path(p)),
                (None, Some(p)) => Binding::All(parse_path(p)),
                (None, None) => Binding::Root,
            };
            if block.conditions.is_empty() {
                bail!("rule `{}`: a match block has no conditions", spec.name);
            }
            let mut conditions = Vec::with_capacity(block.conditions.len());
            for (path, pred) in &block.conditions {
                if pred == &Predicate::default() {
                    bail!("rule `{}`: condition `{path}` has no operator", spec.name);
                }
                let compiled = CompiledPredicate {
                    any_of: pred.any_of.clone(),
                    none_of: pred.none_of.clone(),
                    glob: pred
                        .glob
                        .as_ref()
                        .map(|g| build_globs(g, &spec.name, path))
                        .transpose()?,
                    none_glob: pred
                        .none_glob
                        .as_ref()
                        .map(|g| build_globs(g, &spec.name, path))
                        .transpose()?,
                    matches: pred
                        .matches
                        .as_ref()
                        .map(|r| {
                            Regex::new(r).with_context(|| {
                                format!("rule `{}`: bad regex `{r}` at `{path}`", spec.name)
                            })
                        })
                        .transpose()?,
                    is: pred.is,
                };
                conditions.push((path.clone(), parse_path(path), compiled));
            }
            blocks.push(CompiledBlock {
                binding,
                conditions,
            });
        }
        Ok(Rule { spec, blocks })
    }

    pub(super) fn block_holds(block: &CompiledBlock, binding: &Value) -> bool {
        block
            .conditions
            .iter()
            .all(|(_, path, pred)| pred.holds(resolve(binding, path)))
    }

    /// Element indices of `parsed.segments` that satisfy a whole block, which
    /// is what a rewrite needs in order to know where to splice.
    pub(super) fn matching_segments(&self, doc: &Value) -> Vec<usize> {
        let mut hits = Vec::new();
        for block in &self.blocks {
            let Binding::Any(path) = &block.binding else {
                continue;
            };
            let Some(Value::Array(items)) = resolve(doc, path) else {
                continue;
            };
            for (i, item) in items.iter().enumerate() {
                if Self::block_holds(block, item) && !hits.contains(&i) {
                    hits.push(i);
                }
            }
        }
        hits.sort_unstable();
        hits
    }

    /// Whether a command line trips this rule on its own, which is what an
    /// example in the config asserts. Only the rule's own predicates are asked;
    /// nothing else in the stack takes part.
    pub fn fires_on(&self, command: &str, cwd: Option<&Path>) -> bool {
        let input = json!({ "command": command });
        let (_, doc) = document("Bash", &input, cwd);
        self.matches(&doc)
    }

    /// What a rewrite would turn a command into, for an example to show next to
    /// it. No PATH gate: the illustration is true wherever it is read, even
    /// where the replacement binary is missing.
    pub fn preview(&self, command: &str, cwd: Option<&Path>) -> Option<String> {
        let Action::Rewrite {
            replace_head,
            drop_args,
            add_args,
            ..
        } = &self.spec.action
        else {
            return None;
        };
        let input = json!({ "command": command });
        let (segments, doc) = document("Bash", &input, cwd);
        let hits = self.matching_segments(&doc);
        splice(
            command,
            &segments,
            &hits,
            replace_head.as_deref(),
            drop_args,
            add_args,
        )
    }

    /// Whether the call is even the kind of thing this rule speaks to. An
    /// ungated rule speaks to every tool.
    pub(super) fn applies_to(&self, doc: &Value) -> bool {
        match &self.spec.tool {
            Some(tool) => doc.get("tool_name").and_then(Value::as_str) == Some(tool.as_str()),
            None => true,
        }
    }

    pub(super) fn matches(&self, doc: &Value) -> bool {
        if !self.applies_to(doc) {
            return false;
        }
        self.blocks.iter().any(|block| match &block.binding {
            Binding::Root => Self::block_holds(block, doc),
            Binding::Any(path) => match resolve(doc, path) {
                Some(Value::Array(items)) => {
                    items.iter().any(|item| Self::block_holds(block, item))
                }
                _ => false,
            },
            Binding::All(path) => match resolve(doc, path) {
                Some(Value::Array(items)) => {
                    !items.is_empty() && items.iter().all(|item| Self::block_holds(block, item))
                }
                _ => false,
            },
        })
    }
}

impl CompiledPredicate {
    /// One entry per operator the condition carries. A missing path fails the
    /// positive operators and passes the negative ones: nothing is there to
    /// match, and nothing is there to violate.
    pub(super) fn checks(&self, value: Option<&Value>) -> Vec<(&'static str, bool)> {
        let candidates = candidates(value);
        let mut checks = Vec::new();
        if let Some(list) = &self.any_of {
            checks.push((
                "any_of",
                candidates.iter().any(|c| list.iter().any(|w| w == c)),
            ));
        }
        if let Some(list) = &self.none_of {
            checks.push((
                "none_of",
                !candidates.iter().any(|c| list.iter().any(|w| w == c)),
            ));
        }
        if let Some(set) = &self.glob {
            checks.push(("glob", candidates.iter().any(|c| set.is_match(c))));
        }
        if let Some(set) = &self.none_glob {
            checks.push(("none_glob", !candidates.iter().any(|c| set.is_match(c))));
        }
        if let Some(re) = &self.matches {
            checks.push(("matches", candidates.iter().any(|c| re.is_match(c))));
        }
        if let Some(expected) = self.is {
            checks.push(("is", value.and_then(Value::as_bool) == Some(expected)));
        }
        checks
    }

    /// Deciding and explaining run the same evaluation, so a report can never
    /// disagree with the decision it is reporting on.
    fn holds(&self, value: Option<&Value>) -> bool {
        self.checks(value).into_iter().all(|(_, held)| held)
    }
}

/// A string value contributes itself; an array contributes each of its string
/// elements, so `args` and `file_path` read the same way.
fn candidates(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::document::enrich;
    use super::*;
    use crate::shell;
    use serde::Deserialize;

    fn rule(toml_src: &str) -> Rule {
        #[derive(Deserialize)]
        struct Wrapper {
            rules: Vec<RuleSpec>,
        }
        let w: Wrapper = toml::from_str(toml_src).expect("parse");
        Rule::compile(w.rules.into_iter().next().unwrap()).expect("compile")
    }

    const GREP: &str = r#"
[[rules]]
name = "t"
tool = "Bash"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["grep"] }
pipeline_start = { is = true }
[rules.action]
kind = "deny"
message = "no"
"#;

    fn bash(cmd: &str) -> Value {
        json!({ "command": cmd })
    }

    fn doc(tool_name: &str, tool_input: &Value) -> Value {
        let command = tool_input
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        enrich(
            tool_name,
            tool_input,
            &shell::lex(command),
            Some(Path::new("/workspace")),
        )
    }

    #[test]
    fn conditions_in_a_block_bind_to_one_element() {
        let r = rule(GREP);
        assert!(r.matches(&doc("Bash", &bash("grep foo x"))));
        // `gh` supplies the pipeline start and `grep` the head; neither segment
        // satisfies both, so the block must not hold.
        assert!(!r.matches(&doc("Bash", &bash("gh pr list | grep foo"))));
    }

    #[test]
    fn tool_gate_is_exact() {
        let r = rule(GREP);
        assert!(!r.matches(&doc("Edit", &json!({ "file_path": "grep" }))));
    }

    #[test]
    fn root_bound_block_reads_tool_input_directly() {
        let r = rule(
            r#"
[[rules]]
name = "t"
[[rules.match]]
file_path = { glob = ["*/secrets/*"] }
[rules.action]
kind = "context"
message = "careful"
"#,
        );
        assert!(r.matches(&doc("Edit", &json!({"file_path": "a/secrets/b"}))));
        assert!(!r.matches(&doc("Edit", &json!({"file_path": "a/b"}))));
    }

    #[test]
    fn missing_path_fails_positive_and_passes_negative() {
        let pred = CompiledPredicate {
            any_of: Some(vec!["x".into()]),
            ..Default::default()
        };
        assert!(!pred.holds(None));
        let pred = CompiledPredicate {
            none_of: Some(vec!["x".into()]),
            ..Default::default()
        };
        assert!(pred.holds(None));
    }
}

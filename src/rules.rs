// The predicate language and the engine that runs it.
//
// One vocabulary matches every tool. A rule addresses `file_path` on an Edit
// payload and `parsed.segments[].head` on a Bash one through the same path
// syntax, because shell awareness is a pre-processing step that hangs a
// `parsed` object off the payload rather than a second config dialect.
//
// Two shapes carry most of the design:
//
// A rule's `[[rules.match]]` blocks are OR'd, and the conditions inside one
// block are AND'd against a single binding. That matters for correlation: a
// block bound with `any = "parsed.segments"` asks whether *one* segment
// satisfies every condition, so `cd /repo && grep foo` cannot pass by having
// one segment supply the head and another supply the pipeline position.
//
// A rewrite is gated on its replacement binary existing, in the engine rather
// than per rule. `trash` is absent from the Linux VMs, and a `trash-over-rm`
// rewrite that fired there would turn every delete into a missing command.

use crate::shell::{self, Segment, Span};
use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Exact `tool_name` gate. Absent means the rule sees every tool.
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(rename = "match", default)]
    pub blocks: Vec<MatchBlock>,
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatchBlock {
    /// Path to an array; the block holds when some element satisfies it.
    #[serde(default)]
    pub any: Option<String>,
    /// Path to an array; the block holds when every element satisfies it, and
    /// an empty array never satisfies it.
    #[serde(default)]
    pub all: Option<String>,
    #[serde(flatten)]
    pub conditions: BTreeMap<String, Predicate>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    pub any_of: Option<Vec<String>>,
    pub none_of: Option<Vec<String>>,
    pub glob: Option<Vec<String>>,
    pub none_glob: Option<Vec<String>>,
    pub matches: Option<String>,
    pub is: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Action {
    Deny {
        message: String,
    },
    Rewrite {
        /// Binary that replaces the matched segment's head.
        replace_head: String,
        /// Arguments dropped from the matched segment, matched exactly.
        #[serde(default)]
        drop_args: Vec<String>,
        #[serde(default)]
        message: String,
    },
    Context {
        message: String,
    },
}

impl Action {
    fn outcome(&self) -> Outcome {
        match self {
            Action::Deny { .. } => Outcome::Deny,
            Action::Rewrite { .. } => Outcome::Rewrite,
            Action::Context { .. } => Outcome::Context,
        }
    }

    fn message(&self) -> &str {
        match self {
            Action::Deny { message } | Action::Context { message } => message,
            Action::Rewrite { message, .. } => message,
        }
    }
}

/// A rule with its globs and regexes compiled once at load.
pub struct Rule {
    pub spec: RuleSpec,
    blocks: Vec<CompiledBlock>,
}

struct CompiledBlock {
    binding: Binding,
    conditions: Vec<(Vec<PathPart>, CompiledPredicate)>,
}

enum Binding {
    Root,
    Any(Vec<PathPart>),
    All(Vec<PathPart>),
}

#[derive(Default)]
struct CompiledPredicate {
    any_of: Option<Vec<String>>,
    none_of: Option<Vec<String>>,
    glob: Option<GlobSet>,
    none_glob: Option<GlobSet>,
    matches: Option<Regex>,
    is: Option<bool>,
}

enum PathPart {
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

fn resolve<'a>(value: &'a Value, path: &[PathPart]) -> Option<&'a Value> {
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
                conditions.push((parse_path(path), compiled));
            }
            blocks.push(CompiledBlock {
                binding,
                conditions,
            });
        }
        Ok(Rule { spec, blocks })
    }

    fn block_holds(block: &CompiledBlock, binding: &Value) -> bool {
        block
            .conditions
            .iter()
            .all(|(path, pred)| pred.holds(resolve(binding, path)))
    }

    /// Element indices of `parsed.segments` that satisfy a whole block, which
    /// is what a rewrite needs in order to know where to splice.
    fn matching_segments(&self, doc: &Value) -> Vec<usize> {
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

    fn matches(&self, doc: &Value) -> bool {
        if let Some(tool) = &self.spec.tool {
            if doc.get("tool_name").and_then(Value::as_str) != Some(tool.as_str()) {
                return false;
            }
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
    /// A missing path fails the positive operators and passes the negative
    /// ones: nothing is there to match, and nothing is there to violate.
    fn holds(&self, value: Option<&Value>) -> bool {
        if let Some(expected) = self.is {
            if value.and_then(Value::as_bool) != Some(expected) {
                return false;
            }
        }
        let candidates = candidates(value);
        if let Some(list) = &self.any_of {
            if !candidates.iter().any(|c| list.iter().any(|w| w == c)) {
                return false;
            }
        }
        if let Some(list) = &self.none_of {
            if candidates.iter().any(|c| list.iter().any(|w| w == c)) {
                return false;
            }
        }
        if let Some(set) = &self.glob {
            if !candidates.iter().any(|c| set.is_match(c)) {
                return false;
            }
        }
        if let Some(set) = &self.none_glob {
            if candidates.iter().any(|c| set.is_match(c)) {
                return false;
            }
        }
        if let Some(re) = &self.matches {
            if !candidates.iter().any(|c| re.is_match(c)) {
                return false;
            }
        }
        true
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

/// Projects the payload into the document rules match against. The segments
/// come in already lexed so that one shell parse serves both matching and the
/// spans a rewrite splices with.
fn enrich(tool_name: &str, tool_input: &Value, segments: &[Segment]) -> Value {
    let mut doc = tool_input.as_object().cloned().unwrap_or_default();
    doc.insert("tool_name".into(), json!(tool_name));
    doc.insert(
        "parsed".into(),
        json!({ "segments": segment_docs(segments) }),
    );
    Value::Object(doc)
}

fn segment_docs(segments: &[Segment]) -> Vec<Value> {
    segments
        .iter()
        .map(|s| {
            json!({
                "head": s.head,
                "args": s.args,
                "pipeline_start": s.pipeline_start,
                "depth": s.depth,
                "wrappers": s.wrappers,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Allow,
    Context,
    Rewrite,
    Deny,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Context => "context",
            Outcome::Rewrite => "rewrite",
            Outcome::Deny => "deny",
        }
    }
}

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
pub fn evaluate(rules: &[Rule], tool_name: &str, tool_input: &Value) -> Decision {
    let command = tool_input
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let segments = if tool_name == "Bash" {
        shell::lex(command)
    } else {
        Vec::new()
    };
    let doc = enrich(tool_name, tool_input, &segments);

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
                ..
            } => {
                if !on_path(replace_head) {
                    skipped.push((
                        rule.spec.name.clone(),
                        format!("`{replace_head}` is not on PATH"),
                    ));
                    continue;
                }
                // A rule that matches but cannot be spliced has not fired, and
                // must not contribute its reason to the message either.
                let hits = rule.matching_segments(&doc);
                match splice(command, &segments, &hits, replace_head, drop_args) {
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
        .map(|rule| rule.spec.action.message().trim())
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
                ..
            } = &rule.spec.action
            else {
                continue;
            };
            if let Some(fields) = input.as_object_mut() {
                fields.insert("command".into(), json!(current));
            }
            let segments = shell::lex(&current);
            let doc = enrich(tool_name, &input, &segments);
            let hits = rule.matching_segments(&doc);
            if let Some(next) = splice(&current, &segments, &hits, replace_head, drop_args) {
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

/// Replaces each matched segment's head in place and deletes the dropped
/// arguments, editing the original string so untouched text survives verbatim.
fn splice(
    command: &str,
    segments: &[Segment],
    hits: &[usize],
    replace_head: &str,
    drop_args: &[String],
) -> Option<String> {
    let mut edits: Vec<(Span, &str)> = Vec::new();
    for &i in hits {
        let segment = segments.get(i)?;
        let head_span = segment.head_span?;
        edits.push((head_span, replace_head));
        for (arg, span) in segment.args.iter().zip(&segment.arg_spans) {
            if drop_args.iter().any(|d| d == arg) {
                edits.push(((*span)?, ""));
            }
        }
    }
    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|(span, _)| span.start);

    let bytes = command.as_bytes();
    let mut out = String::with_capacity(command.len());
    let mut cursor = 0;
    for (span, replacement) in edits {
        let mut start = span.start;
        // A deletion takes its leading whitespace with it, so removing `-rf`
        // does not leave a double space behind.
        if replacement.is_empty() {
            while start > cursor && matches!(bytes[start - 1], b' ' | b'\t') {
                start -= 1;
            }
        }
        if start < cursor {
            continue;
        }
        out.push_str(&command[cursor..start]);
        out.push_str(replacement);
        cursor = span.end;
    }
    out.push_str(&command[cursor..]);
    Some(out)
}

/// Direct PATH scan rather than a `which` subprocess; the hook runs on every
/// tool call and a fork would dominate its budget.
fn on_path(binary: &str) -> bool {
    if binary.contains('/') {
        return is_executable(Path::new(binary));
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable(&dir.join(binary)))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        enrich(tool_name, tool_input, &shell::lex(command))
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

    #[test]
    fn splice_replaces_head_and_drops_flags() {
        let cmd = "cd x && rm -rf build node_modules";
        let segments = shell::lex(cmd);
        let out = splice(cmd, &segments, &[1], "trash", &["-rf".to_string()]).unwrap();
        assert_eq!(out, "cd x && trash build node_modules");
    }

    #[test]
    fn splice_declines_nested_text() {
        let cmd = "bash -c 'rm -rf build'";
        let segments = shell::lex(cmd);
        assert!(splice(cmd, &segments, &[0], "trash", &[]).is_none());
    }
}

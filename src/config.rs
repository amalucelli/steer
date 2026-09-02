// Rule sources and how they stack.
//
// Built-ins are compiled in and active, a global file under XDG config holds
// what dotfiles manage, and a repo may drop `.steer.toml` to append rules or
// disable inherited ones by name. Later sources override earlier definitions of
// the same name; strongest-wins in the engine means an overlay still cannot
// weaken a deny, only replace the rule outright.

use crate::rules::{Action, Message, Predicate, Rule, RuleSpec};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const BUILTIN: &str = include_str!("builtin.toml");
const OVERLAY_NAME: &str = ".steer.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Rule names switched off, whatever source defined them.
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

pub struct Source {
    pub label: String,
    pub text: String,
}

/// A rule written back out as TOML, in the shape the config files use. Whole
/// rule, never a fragment: a later source can only replace a rule of the same
/// name, not add to it, so a draft is pasteable only if it carries everything.
///
/// Hand-written rather than derived: `serde`'s TOML output spells a predicate
/// as its own `[rules.match.head]` table, which parses but looks nothing like
/// what a person maintains.
pub fn to_toml(spec: &RuleSpec) -> String {
    let mut out = String::from("[[rules]]\n");
    out.push_str(&format!("name = {}\n", string(&spec.name)));
    if !spec.description.is_empty() {
        out.push_str(&format!("description = {}\n", string(&spec.description)));
    }
    if let Some(tool) = &spec.tool {
        out.push_str(&format!("tool = {}\n", string(tool)));
    }
    if let Some(agents) = &spec.agents {
        let names: Vec<String> = agents.iter().map(|a| a.as_str().to_string()).collect();
        out.push_str(&format!("agents = {}\n", array(&names)));
    }
    for block in &spec.blocks {
        out.push_str("\n[[rules.match]]\n");
        if let Some(path) = &block.any {
            out.push_str(&format!("any = {}\n", string(path)));
        }
        if let Some(path) = &block.all {
            out.push_str(&format!("all = {}\n", string(path)));
        }
        for (path, predicate) in &block.conditions {
            out.push_str(&format!("{} = {}\n", key(path), inline(predicate)));
        }
    }

    out.push_str("\n[rules.action]\n");
    out.push_str(&format!(
        "kind = {}\n",
        string(spec.action.outcome().as_str())
    ));
    if let Action::Rewrite {
        replace_head,
        drop_args,
        add_args,
        ..
    } = &spec.action
    {
        if let Some(head) = replace_head {
            out.push_str(&format!("replace_head = {}\n", string(head)));
        }
        if !drop_args.is_empty() {
            out.push_str(&format!("drop_args = {}\n", array(drop_args)));
        }
        if !add_args.is_empty() {
            out.push_str(&format!("add_args = {}\n", array(add_args)));
        }
    }
    let rewrite = matches!(spec.action, Action::Rewrite { .. });
    out.push_str(&message_toml(spec.action.message(), rewrite));

    // Last, after the action's own tables: a section opened earlier would
    // capture every key that followed it.
    let test = &spec.test;
    if !test.fires.is_empty() || !test.ignores.is_empty() || !test.rewrites.is_empty() {
        out.push_str("\n[rules.test]\n");
        if !test.fires.is_empty() {
            out.push_str(&format!("fires = {}\n", array(&test.fires)));
        }
        if !test.ignores.is_empty() {
            out.push_str(&format!("ignores = {}\n", array(&test.ignores)));
        }
        if !test.rewrites.is_empty() {
            let pairs: Vec<String> = test
                .rewrites
                .iter()
                .map(|(command, want)| format!("{} = {}", string(command), string(want)))
                .collect();
            out.push_str(&format!("rewrites = {{ {} }}\n", pairs.join(", ")));
        }
    }
    out
}

/// A per-harness message is a table, so it has to follow every scalar the
/// action carries.
///
/// `omit_empty` is the rewrite case, where the field defaults and writing an
/// empty one back out is noise. Deny and context require it, and a drafted rule
/// carries an empty one deliberately — as the blank the author fills in.
fn message_toml(message: &Message, omit_empty: bool) -> String {
    match message {
        Message::Every(text) if text.is_empty() && omit_empty => String::new(),
        Message::Every(text) => format!("message = {}\n", string(text)),
        Message::PerAgent(per) => {
            let mut out = String::from("\n[rules.action.message]\n");
            for (agent, text) in per {
                out.push_str(&format!("{} = {}\n", agent.as_str(), string(text)));
            }
            out
        }
    }
}

fn inline(predicate: &Predicate) -> String {
    let mut parts = Vec::new();
    if let Some(values) = &predicate.any_of {
        parts.push(format!("any_of = {}", array(values)));
    }
    if let Some(values) = &predicate.none_of {
        parts.push(format!("none_of = {}", array(values)));
    }
    if let Some(patterns) = &predicate.glob {
        parts.push(format!("glob = {}", array(patterns)));
    }
    if let Some(patterns) = &predicate.none_glob {
        parts.push(format!("none_glob = {}", array(patterns)));
    }
    if let Some(pattern) = &predicate.matches {
        parts.push(format!("matches = {}", string(pattern)));
    }
    if let Some(expected) = predicate.is {
        parts.push(format!("is = {expected}"));
    }
    format!("{{ {} }}", parts.join(", "))
}

fn array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| string(value)).collect();
    format!("[{}]", items.join(", "))
}

/// A dotted path like `args.0` is not a bare key, and unquoted it would address
/// a nested table instead of a condition.
fn key(path: &str) -> String {
    let bare = !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    match bare {
        true => path.to_string(),
        false => string(path),
    }
}

/// A multi-line value takes a `"""` block, which is how the messages are
/// written by hand and the only way they stay readable.
fn string(text: &str) -> String {
    if !text.contains('\n') {
        return quoted(text);
    }
    let body = text.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    // A body ending in a quote would run into the closing delimiter.
    let body = match body.ends_with('"') {
        true => format!("{}\\\"", &body[..body.len() - 1]),
        false => body,
    };
    format!("\"\"\"\n{body}\"\"\"")
}

fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn global_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("steer").join("config.toml"))
}

pub fn overlay_path(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .map(|dir| dir.join(OVERLAY_NAME))
        .find(|candidate| candidate.is_file())
}

pub fn sources(cwd: &Path) -> Result<Vec<Source>> {
    let mut sources = vec![Source {
        label: "built-in".into(),
        text: BUILTIN.to_string(),
    }];
    for path in [global_path(), overlay_path(cwd)].into_iter().flatten() {
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        sources.push(Source {
            label: path.display().to_string(),
            text,
        });
    }
    Ok(sources)
}

pub fn load(cwd: &Path) -> Result<Vec<Rule>> {
    let mut specs: Vec<RuleSpec> = Vec::new();
    let mut disabled: Vec<String> = Vec::new();

    for source in sources(cwd)? {
        let file: ConfigFile =
            toml::from_str(&source.text).with_context(|| format!("parsing {}", source.label))?;
        disabled.extend(file.disable);
        upsert(&mut specs, file.rules);
    }

    specs.retain(|spec| !disabled.contains(&spec.name));
    specs.into_iter().map(Rule::compile).collect()
}

/// A later source replaces an earlier definition of the same name rather than
/// adding a second rule under it.
fn upsert(specs: &mut Vec<RuleSpec>, incoming: Vec<RuleSpec>) {
    for spec in incoming {
        match specs.iter_mut().find(|s| s.name == spec.name) {
            Some(existing) => *existing = spec,
            None => specs.push(spec),
        }
    }
}

pub struct Problem {
    pub location: String,
    pub detail: String,
}

/// One source as it was declared, before the stack collapses it.
pub struct Layer {
    pub label: String,
    /// Absent when the source did not parse; the problem carries the detail.
    pub rules: Option<Vec<RuleSpec>>,
    pub disable: Vec<String>,
}

pub struct Report {
    pub layers: Vec<Layer>,
    pub problems: Vec<Problem>,
}

/// Every problem in every source, rather than the first one, so a broken config
/// takes one edit to fix instead of one per round trip. The layers come back
/// alongside them: what each source declared is what makes an override or a
/// disable readable, and it is gone once `load` has stacked them.
pub fn inspect(cwd: &Path) -> Result<Report> {
    #[derive(Deserialize)]
    struct Located {
        #[serde(default)]
        disable: Vec<toml::Spanned<String>>,
        #[serde(default)]
        rules: Vec<LocatedRule>,
    }
    #[derive(Deserialize)]
    struct LocatedRule {
        name: toml::Spanned<String>,
        #[serde(default)]
        test: LocatedTest,
    }
    #[derive(Default, Deserialize)]
    struct LocatedTest {
        #[serde(default)]
        fires: Vec<toml::Spanned<String>>,
        #[serde(default)]
        ignores: Vec<toml::Spanned<String>>,
        #[serde(default)]
        rewrites: BTreeMap<String, toml::Spanned<String>>,
    }

    enum Expect {
        Fires,
        Ignores,
        /// Fires, and produces exactly this.
        Rewrites(String),
    }

    struct Example {
        expect: Expect,
        command: String,
        location: String,
    }

    let mut problems = Vec::new();
    let mut layers: Vec<Layer> = Vec::new();
    let mut disables: Vec<(String, String)> = Vec::new();
    let mut specs: Vec<RuleSpec> = Vec::new();
    // Keyed by rule name and replaced wholesale by a later source, so examples
    // follow the definition that is actually live.
    let mut examples: BTreeMap<String, Vec<Example>> = BTreeMap::new();

    for source in sources(cwd)? {
        let file: ConfigFile = match toml::from_str(&source.text) {
            Ok(file) => file,
            Err(err) => {
                problems.push(Problem {
                    location: source.label.clone(),
                    detail: err.to_string().trim().to_string(),
                });
                layers.push(Layer {
                    label: source.label.clone(),
                    rules: None,
                    disable: Vec::new(),
                });
                continue;
            }
        };
        // Cannot fail where the parse above succeeded: `Located` reads the
        // same file with a looser schema, purely to recover spans.
        let located: Located = toml::from_str(&source.text)?;

        let mut seen: Vec<String> = Vec::new();
        for rule in &located.rules {
            let name = rule.name.get_ref();
            if seen.contains(name) {
                problems.push(Problem {
                    location: at(&source, rule.name.span().start),
                    detail: format!("duplicate rule name `{name}` in this file"),
                });
            }
            seen.push(name.clone());

            let declared = rule
                .test
                .fires
                .iter()
                .map(|example| Example {
                    expect: Expect::Fires,
                    command: example.get_ref().clone(),
                    location: at(&source, example.span().start),
                })
                .chain(rule.test.ignores.iter().map(|example| Example {
                    expect: Expect::Ignores,
                    command: example.get_ref().clone(),
                    location: at(&source, example.span().start),
                }))
                .chain(rule.test.rewrites.iter().map(|(command, want)| Example {
                    expect: Expect::Rewrites(want.get_ref().clone()),
                    command: command.clone(),
                    location: at(&source, want.span().start),
                }))
                .collect();
            examples.insert(name.clone(), declared);
        }
        for name in &located.disable {
            disables.push((name.get_ref().clone(), at(&source, name.span().start)));
        }

        layers.push(Layer {
            label: source.label.clone(),
            rules: Some(file.rules.clone()),
            disable: file.disable,
        });
        upsert(&mut specs, file.rules);
    }

    for (name, location) in &disables {
        if !specs.iter().any(|s| &s.name == name) {
            problems.push(Problem {
                location: location.clone(),
                detail: format!("disable names `{name}`, which no rule defines"),
            });
        }
    }
    let disabled: Vec<String> = disables.into_iter().map(|(name, _)| name).collect();

    for spec in specs {
        let name = spec.name.clone();
        // A rule switched off still gets compiled, so a broken one is reported
        // rather than hidden by the `disable` that happens to cover it. Its
        // examples are another matter: they assert what the stack does, and a
        // disabled rule does nothing.
        let live = !disabled.contains(&name);
        let tool = spec.tool.clone();
        let rule = match Rule::compile(spec) {
            Ok(rule) => rule,
            Err(err) => {
                problems.push(Problem {
                    location: format!("rule `{name}`"),
                    detail: format!("{err:#}"),
                });
                continue;
            }
        };
        if !live {
            continue;
        }
        for example in examples.get(&name).into_iter().flatten() {
            if tool.as_deref().is_some_and(|tool| tool != "Bash") {
                problems.push(Problem {
                    location: example.location.clone(),
                    detail: format!("examples are Bash command lines, and rule `{name}` is gated on another tool"),
                });
                continue;
            }
            let fires = rule.fires_on(&example.command, Some(cwd));
            let detail = match &example.expect {
                Expect::Fires if !fires => Some(format!(
                    "`fires` example {:?} does not fire `{name}`",
                    example.command
                )),
                Expect::Ignores if fires => Some(format!(
                    "`ignores` example {:?} fires `{name}`",
                    example.command
                )),
                // No PATH gate on the preview, so this holds on a machine
                // without the replacement binary too.
                Expect::Rewrites(want) => match rule.preview(&example.command, Some(cwd)) {
                    Some(got) if &got == want => None,
                    Some(got) => Some(format!(
                        "`rewrites` example {:?} produces {got:?}, not {want:?}",
                        example.command
                    )),
                    None => Some(format!(
                        "`rewrites` example {:?} does not rewrite under `{name}`",
                        example.command
                    )),
                },
                _ => None,
            };
            if let Some(detail) = detail {
                problems.push(Problem {
                    location: example.location.clone(),
                    detail,
                });
            }
        }
    }

    Ok(Report { layers, problems })
}

fn at(source: &Source, offset: usize) -> String {
    let head = source.text.get(..offset).unwrap_or("");
    let line = head.matches('\n').count() + 1;
    let column = head
        .rsplit('\n')
        .next()
        .map_or(1, |l| l.chars().count() + 1);
    format!("{}:{line}:{column}", source.label)
}

pub fn init(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, STARTER).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

const STARTER: &str = r#"# steer config. Built-in rules are active without this file; everything here
# adds to them or switches them off.

# Turn off a built-in by name. A repo with no fff index wants this one:
# disable = ["fff-over-grep"]

# A rule fires when ANY of its [[rules.match]] blocks holds, and a block holds
# when EVERY condition in it holds against ONE binding. `any` binds the block to
# the elements of an array, so the conditions below all describe the same
# pipeline segment.
#
# Operators: any_of, none_of, glob, none_glob, matches, is.
# Actions: deny (message), rewrite (replace_head, drop_args), context (message).

# `fires` and `ignores` are example commands that `steer validate` runs, so the
# edges of a rule stay checked rather than remembered.

# [[rules]]
# name = "jq-over-python-json"
# tool = "Bash"
# fires = ["python3 -c 'json.loads(open(\"a.json\").read())'"]
# ignores = ["jq .name a.json"]
#
# [[rules.match]]
# any = "parsed.segments"
# head = { any_of = ["python", "python3"] }
# args = { matches = "json\\.loads" }
#
# [rules.action]
# kind = "deny"
# message = "Use jq for one-off JSON reshaping."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    // The emitter is written by hand, so nothing but this stops a field added
    // to `RuleSpec` from being dropped on the way out — and a dropped field is
    // silent: the paste parses, and the rule it defines is not the one it
    // replaced.
    #[test]
    fn every_built_in_survives_a_round_trip_through_the_emitter() {
        let file: ConfigFile = toml::from_str(BUILTIN).expect("parse built-ins");
        for spec in file.rules {
            let text = to_toml(&spec);
            let back: ConfigFile = toml::from_str(&text).unwrap_or_else(|e| {
                panic!(
                    "emitted TOML for `{}` does not parse: {e}\n{text}",
                    spec.name
                )
            });
            assert_eq!(
                back.rules.first(),
                Some(&spec),
                "`{}` changed on the way out:\n{text}",
                spec.name
            );
        }
    }

    #[test]
    fn builtins_compile() {
        let file: ConfigFile = toml::from_str(BUILTIN).expect("parse built-ins");
        assert_eq!(file.rules.len(), 4);
        for spec in file.rules {
            Rule::compile(spec).expect("compile built-in");
        }
    }
}

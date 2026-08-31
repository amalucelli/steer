// Rule sources and how they stack.
//
// Built-ins are compiled in and active, a global file under XDG config holds
// what dotfiles manage, and a repo may drop `.steer.toml` to append rules or
// disable inherited ones by name. Later sources override earlier definitions of
// the same name; strongest-wins in the engine means an overlay still cannot
// weaken a deny, only replace the rule outright.

use crate::rules::{Rule, RuleSpec};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
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

/// Every problem in every source, rather than the first one, so a broken config
/// takes one edit to fix instead of one per round trip.
pub fn validate(cwd: &Path) -> Result<Vec<Problem>> {
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
    }

    let mut problems = Vec::new();
    let mut disables: Vec<(String, String)> = Vec::new();
    let mut specs: Vec<RuleSpec> = Vec::new();

    for source in sources(cwd)? {
        let file: ConfigFile = match toml::from_str(&source.text) {
            Ok(file) => file,
            Err(err) => {
                problems.push(Problem {
                    location: source.label.clone(),
                    detail: err.to_string().trim().to_string(),
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
        }
        for name in &located.disable {
            disables.push((name.get_ref().clone(), at(&source, name.span().start)));
        }

        upsert(&mut specs, file.rules);
    }

    for (name, location) in disables {
        if !specs.iter().any(|s| s.name == name) {
            problems.push(Problem {
                location,
                detail: format!("disable names `{name}`, which no rule defines"),
            });
        }
    }

    for spec in specs {
        let name = spec.name.clone();
        if let Err(err) = Rule::compile(spec) {
            problems.push(Problem {
                location: format!("rule `{name}`"),
                detail: format!("{err:#}"),
            });
        }
    }

    Ok(problems)
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

# [[rules]]
# name = "jq-over-python-json"
# tool = "Bash"
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

    #[test]
    fn builtins_compile() {
        let file: ConfigFile = toml::from_str(BUILTIN).expect("parse built-ins");
        assert_eq!(file.rules.len(), 4);
        for spec in file.rules {
            Rule::compile(spec).expect("compile built-in");
        }
    }
}

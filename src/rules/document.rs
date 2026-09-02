// The payload projected into the document predicates read.
//
// One vocabulary matches every tool. A rule addresses `file_path` on an Edit
// payload and `parsed.segments[].head` on a Bash one through the same path
// syntax, because shell awareness is a pre-processing step that hangs a
// `parsed` object off the payload rather than a second config dialect.

use crate::shell::{self, Segment};
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};

/// The lexed command and the document the predicates read, which every entry
/// point into the engine needs before it can ask a rule anything. The segments
/// come back alongside it so that one shell parse serves both matching and the
/// spans a rewrite splices with. Only Bash carries a command line; every other
/// tool is matched on its input alone.
pub(super) fn document(
    tool_name: &str,
    tool_input: &Value,
    cwd: Option<&Path>,
) -> (Vec<Segment>, Value) {
    let segments = match tool_name {
        "Bash" => shell::lex(
            tool_input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        _ => Vec::new(),
    };
    let doc = enrich(tool_name, tool_input, &segments, cwd);
    (segments, doc)
}

pub(super) fn enrich(
    tool_name: &str,
    tool_input: &Value,
    segments: &[Segment],
    cwd: Option<&Path>,
) -> Value {
    let mut doc = tool_input.as_object().cloned().unwrap_or_default();
    doc.insert("tool_name".into(), json!(tool_name));
    doc.insert(
        "parsed".into(),
        json!({ "segments": segment_docs(segments, cwd) }),
    );
    Value::Object(doc)
}

fn segment_docs(segments: &[Segment], cwd: Option<&Path>) -> Vec<Value> {
    segments
        .iter()
        .map(|s| {
            let mut doc = json!({
                "head": s.head,
                "args": s.args,
                "pipeline_start": s.pipeline_start,
                "depth": s.depth,
                "wrappers": s.wrappers,
            });
            // Left out entirely when there is no cwd to resolve against, so a
            // rule asking for it declines rather than guessing.
            if let (Some(cwd), Some(fields)) = (cwd, doc.as_object_mut()) {
                fields.insert("in_workspace".into(), json!(in_workspace(cwd, &s.args)));
            }
            doc
        })
        .collect()
}

/// Whether a segment reaches into the session's working tree.
///
/// "Outside the workspace" is a question about where a path lands, not how it
/// is spelled. An absolute path into the workspace is the same search as the
/// relative one, and Claude Code writes absolute paths constantly — testing for
/// a leading slash lets most real searches through.
///
/// A command with no path argument works on the current directory, which is
/// the workspace by definition.
pub fn in_workspace(cwd: &Path, args: &[String]) -> bool {
    let workspace = normalize(cwd);
    let mut saw_path = false;
    for arg in args.iter().filter(|a| path_shaped(a)) {
        saw_path = true;
        if let Some(resolved) = resolve_arg(&workspace, arg) {
            if resolved.starts_with(&workspace) {
                return true;
            }
        }
    }
    !saw_path
}

/// Arguments that name a location rather than a pattern or a flag. Glob and
/// regex metacharacters rule a token out: `*chat*` and `func .*Conv` are what
/// the command is looking for, not where.
fn path_shaped(arg: &str) -> bool {
    if arg.is_empty() || arg.starts_with('-') || arg.contains("://") {
        return false;
    }
    if arg.contains(['*', '?', '[', ']', '(', ')', '|', '^', '$', '\\']) {
        return false;
    }
    arg == "." || arg == ".." || arg.starts_with('~') || arg.contains('/')
}

/// Resolves lexically and never touches the disk: a search over a directory
/// that does not exist yet still has a location.
fn resolve_arg(cwd: &Path, arg: &str) -> Option<PathBuf> {
    let expanded = if arg == "~" {
        PathBuf::from(std::env::var_os("HOME")?)
    } else if let Some(rest) = arg.strip_prefix("~/") {
        PathBuf::from(std::env::var_os("HOME")?).join(rest)
    } else if arg.starts_with('~') {
        // `~user` is another account's home and not ours to guess at.
        return None;
    } else {
        PathBuf::from(arg)
    };
    Some(normalize(&if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }))
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_membership_follows_where_a_path_lands() {
        let w = Path::new("/workspace");
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        assert!(in_workspace(w, &args(&["-rn", "X", "/workspace/pkg/go"])));
        assert!(in_workspace(w, &args(&["-rn", "X", "pkg/go"])));
        assert!(in_workspace(w, &args(&["-rn", "X"])), "no path arg is cwd");
        assert!(in_workspace(w, &args(&["-rn", "X", "."])));
        assert!(in_workspace(w, &args(&["-rn", "X", "sub/../pkg"])));

        assert!(!in_workspace(w, &args(&["-rn", "X", "/usr/local/include"])));
        assert!(!in_workspace(w, &args(&["-rn", "X", "../elsewhere/src"])));

        // A pattern is not a location: metacharacters and URLs are ruled out,
        // so they neither claim the workspace nor escape it.
        assert!(!path_shaped("*chat*"));
        assert!(!path_shaped("func .*Conv"));
        assert!(!path_shaped("https://example.com/x"));
        assert!(!path_shaped("--include=*.go"));
        assert!(path_shaped("pkg/go"));
        assert!(path_shaped("."));
    }
}

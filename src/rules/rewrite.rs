// Editing a command line in place, and the PATH lookup that gates whether the
// edit may happen at all.
//
// A rewrite edits the original string through the spans the lexer recorded
// rather than re-serializing the segments. Reconstruction is lossy — quoting,
// spacing, redirections, and everything nested — and the output here is what
// actually runs, so untouched text has to survive byte for byte.

use crate::shell::{Segment, Span};
use std::path::Path;

/// Replaces each matched segment's head in place, deletes the dropped
/// arguments and appends the added ones, editing the original string so
/// untouched text survives verbatim.
pub(super) fn splice(
    command: &str,
    segments: &[Segment],
    hits: &[usize],
    replace_head: Option<&str>,
    drop_args: &[String],
    add_args: &[String],
) -> Option<String> {
    let mut edits: Vec<(Span, String)> = Vec::new();
    for &i in hits {
        let segment = segments.get(i)?;
        if let Some(head) = replace_head {
            edits.push((segment.head_span?, head.to_string()));
        }
        for (arg, span) in segment.args.iter().zip(&segment.arg_spans) {
            if drop_args.iter().any(|d| d == arg) {
                edits.push(((*span)?, String::new()));
            }
        }
        if !add_args.is_empty() {
            let at = insertion_point(segment)?;
            edits.push((
                Span { start: at, end: at },
                format!(" {}", add_args.join(" ")),
            ));
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
        out.push_str(&replacement);
        cursor = span.end;
    }
    out.push_str(&command[cursor..]);
    Some(out)
}

/// Where an appended argument goes: after the segment's last token, but ahead
/// of a `--` separator. By getopt convention everything past `--` is an
/// operand, so a flag written there is read as one — a pathspec, for `git`.
///
/// Redirection targets never reach `args`, so a trailing `> out` is not the
/// last token even though it is the last thing written.
fn insertion_point(segment: &Segment) -> Option<usize> {
    let cut = segment
        .args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(segment.args.len());
    segment.arg_spans[..cut]
        .iter()
        .rev()
        .flatten()
        .next()
        .or(segment.head_span.as_ref())
        .map(|span| span.end)
}

/// Direct PATH scan rather than a `which` subprocess; the hook runs on every
/// tool call and a fork would dominate its budget.
pub fn on_path(binary: &str) -> bool {
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
    use crate::shell;

    #[test]
    fn splice_replaces_head_and_drops_flags() {
        let cmd = "cd x && rm -rf build node_modules";
        let segments = shell::lex(cmd);
        let out = splice(
            cmd,
            &segments,
            &[1],
            Some("trash"),
            &["-rf".to_string()],
            &[],
        )
        .unwrap();
        assert_eq!(out, "cd x && trash build node_modules");
    }

    #[test]
    fn splice_declines_nested_text() {
        let cmd = "bash -c 'rm -rf build'";
        let segments = shell::lex(cmd);
        assert!(splice(cmd, &segments, &[0], Some("trash"), &[], &[]).is_none());
    }
}

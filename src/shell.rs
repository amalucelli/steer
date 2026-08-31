// Turns a Bash command line into the segments rules match against. A "segment"
// is one pipeline stage with its wrappers peeled off, so `sudo timeout 5 grep x`
// and `grep x` both present a head of `grep`.
//
// The split is deliberately asymmetric: `;`, `&&`, `||` and newlines start a new
// command, but `|` only advances the stage within one. A grep after a pipe is
// filtering something that already ran, which is legitimate; a grep at the head
// of a pipeline is a search. Rules distinguish the two through `pipeline_start`.
//
// Spans are recorded so a rewrite action can splice a replacement binary into
// the original string instead of re-serializing a lossy reconstruction. Only
// depth-0 segments carry them — text inside `bash -c '...'` or `$(...)` is a
// nested source with its own coordinates.

// Nested scripts recurse; the cap stops a pathological payload from spinning.
const MAX_DEPTH: u32 = 4;

// Guards against a wrapper handler that fails to advance the cursor.
const MAX_PEEL_STEPS: usize = 64;

const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];

// `for` is absent on purpose: peeling it exposes the loop variable as a head,
// which is noise. The rest either introduce a real command as their next word
// or, for the closing forms, have no word left and yield no segment at all.
const KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "while", "until", "do", "!", "fi", "done", "esac",
];

// git options that take a separate value word. The `--opt=value` spellings need
// no entry; they are one token and skip themselves.
const GIT_VALUED: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--attr-source",
    "--config-env",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Segment {
    /// Basename of the command, so `/usr/bin/grep` and `grep` compare equal.
    pub head: String,
    pub args: Vec<String>,
    /// True when this stage produces output rather than filtering someone else's.
    pub pipeline_start: bool,
    /// 0 for the command line itself, higher inside `bash -c` or `$(...)`.
    pub depth: u32,
    pub wrappers: Vec<String>,
    pub head_span: Option<Span>,
    pub arg_spans: Vec<Option<Span>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Sep,
    Pipe,
    Redirect,
}

#[derive(Debug, Clone)]
struct Word {
    text: String,
    span: Option<Span>,
    /// Command substitutions found inside this word, as raw source.
    subs: Vec<String>,
}

#[derive(Debug, Clone)]
enum Tok {
    Word(Word),
    Op(Op),
}

pub fn lex(command: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    lex_into(command, 0, &mut out);
    out
}

fn lex_into(src: &str, depth: u32, out: &mut Vec<Segment>) {
    if depth > MAX_DEPTH {
        return;
    }
    let toks = tokenize(src, depth == 0);
    for statement in toks.split(|t| matches!(t, Tok::Op(Op::Sep))) {
        for (stage, tokens) in statement
            .split(|t| matches!(t, Tok::Op(Op::Pipe)))
            .enumerate()
        {
            let words = collect_words(tokens);
            peel(&words, depth, stage == 0, out);
            for word in &words {
                for sub in &word.subs {
                    lex_into(sub, depth + 1, out);
                }
            }
        }
    }
}

/// Drops redirection targets so `2>/dev/null` never reaches a rule as an
/// absolute-path argument.
fn collect_words(tokens: &[Tok]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut skip_next = false;
    for tok in tokens {
        match tok {
            Tok::Op(Op::Redirect) => skip_next = true,
            Tok::Op(_) => {}
            Tok::Word(w) => {
                if skip_next {
                    skip_next = false;
                } else {
                    words.push(w.clone());
                }
            }
        }
    }
    words
}

fn tokenize(src: &str, keep_spans: bool) -> Vec<Tok> {
    let bytes = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b' ' || c == b'\t' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b'\n' {
            toks.push(Tok::Op(Op::Sep));
            i += 1;
            continue;
        }
        if c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if let Some(len) = redirect_len(bytes, i) {
            toks.push(Tok::Op(Op::Redirect));
            i += len;
            continue;
        }
        if let Some((op, len)) = operator(bytes, i) {
            toks.push(Tok::Op(op));
            i += len;
            continue;
        }
        let start = i;
        let (word, next) = scan_word(src, i);
        i = next;
        if i == start {
            i += 1;
            continue;
        }
        if !word.text.is_empty() || !word.subs.is_empty() {
            toks.push(Tok::Word(Word {
                span: keep_spans.then_some(Span { start, end: i }),
                ..word
            }));
        }
    }
    toks
}

/// A leading file-descriptor number glued to `<` or `>`, or `&>`.
fn redirect_len(b: &[u8], i: usize) -> Option<usize> {
    if b[i] == b'&' && b.get(i + 1) == Some(&b'>') {
        return Some(if b.get(i + 2) == Some(&b'>') { 3 } else { 2 });
    }
    let mut j = i;
    while j < b.len() && b[j].is_ascii_digit() {
        j += 1;
    }
    if j >= b.len() || (b[j] != b'<' && b[j] != b'>') {
        return None;
    }
    let mut k = j + 1;
    while k < b.len() && matches!(b[k], b'>' | b'<' | b'&') {
        k += 1;
    }
    Some(k - i)
}

fn operator(b: &[u8], i: usize) -> Option<(Op, usize)> {
    let two = b.get(i + 1).copied();
    match b[i] {
        b'&' if two == Some(b'&') => Some((Op::Sep, 2)),
        b'&' => Some((Op::Sep, 1)),
        b'|' if two == Some(b'|') => Some((Op::Sep, 2)),
        b'|' if two == Some(b'&') => Some((Op::Pipe, 2)),
        b'|' => Some((Op::Pipe, 1)),
        b';' if two == Some(b';') => Some((Op::Sep, 2)),
        b';' => Some((Op::Sep, 1)),
        // Subshell and group boundaries end a command the same way `;` does.
        b'(' | b')' => Some((Op::Sep, 1)),
        _ => None,
    }
}

/// Reads one word, resolving quotes and escapes to the literal text a shell
/// would pass as `argv`. Command substitutions contribute no text; their source
/// is set aside to be lexed on its own.
fn scan_word(src: &str, from: usize) -> (Word, usize) {
    let b = src.as_bytes();
    let mut text = String::new();
    let mut subs = Vec::new();
    let mut i = from;

    while i < b.len() {
        match b[i] {
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => break,
            b'\\' => {
                if let Some(&next) = b.get(i + 1) {
                    if next != b'\n' {
                        text.push(next as char);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                let start = i + 1;
                i = start;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                text.push_str(&src[start.min(b.len())..i]);
                i = (i + 1).min(b.len());
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    match b[i] {
                        b'\\' => {
                            if let Some(&next) = b.get(i + 1) {
                                if matches!(next, b'"' | b'\\' | b'$' | b'`') {
                                    text.push(next as char);
                                    i += 2;
                                    continue;
                                }
                            }
                            text.push('\\');
                            i += 1;
                        }
                        b'$' if b.get(i + 1) == Some(&b'(') => {
                            let (inner, next) = balanced(src, i + 1);
                            subs.push(inner);
                            i = next;
                        }
                        b'`' => {
                            let (inner, next) = backtick(src, i);
                            subs.push(inner);
                            i = next;
                        }
                        _ => {
                            push_char(&mut text, src, &mut i);
                        }
                    }
                }
                i = (i + 1).min(b.len());
            }
            b'$' if b.get(i + 1) == Some(&b'(') => {
                let (inner, next) = balanced(src, i + 1);
                subs.push(inner);
                i = next;
            }
            b'`' => {
                let (inner, next) = backtick(src, i);
                subs.push(inner);
                i = next;
            }
            _ => push_char(&mut text, src, &mut i),
        }
    }
    (
        Word {
            text,
            span: None,
            subs,
        },
        i,
    )
}

fn push_char(text: &mut String, src: &str, i: &mut usize) {
    let ch = src[*i..].chars().next().unwrap_or('\0');
    text.push(ch);
    *i += ch.len_utf8();
}

/// Contents of a `(...)` run starting at `open`, and the index just past it.
fn balanced(src: &str, open: usize) -> (String, usize) {
    let b = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (src[open + 1..i].to_string(), i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (src[(open + 1).min(b.len())..].to_string(), b.len())
}

fn backtick(src: &str, open: usize) -> (String, usize) {
    let b = src.as_bytes();
    let mut i = open + 1;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == b'`' {
            return (src[open + 1..i].to_string(), i + 1);
        }
        i += 1;
    }
    (src[(open + 1).min(b.len())..].to_string(), b.len())
}

/// A token is an assignment only when the name before `=` is a shell
/// identifier. A looser test consumes flags like `--include=*.go` and lets the
/// search it belongs to through untouched.
fn is_assignment(w: &str) -> bool {
    let Some(eq) = w.find('=') else {
        return false;
    };
    if eq == 0 {
        return false;
    }
    let mut chars = w[..eq].chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn skip_flags(words: &[Word], i: &mut usize, valued: &[&str]) {
    while *i < words.len() {
        let w = words[*i].text.as_str();
        if w == "--" {
            *i += 1;
            return;
        }
        if !w.starts_with('-') || w == "-" {
            return;
        }
        let step = if valued.contains(&w) { 2 } else { 1 };
        *i = (*i + step).min(words.len());
    }
}

fn peel(words: &[Word], depth: u32, pipeline_start: bool, out: &mut Vec<Segment>) {
    let mut i = 0;
    let mut wrappers = Vec::new();

    for _ in 0..MAX_PEEL_STEPS {
        let Some(word) = words.get(i) else { return };
        let w = word.text.as_str();

        if is_assignment(w) {
            wrappers.push(w.to_string());
            i += 1;
            continue;
        }

        let name = basename(w);
        let before = i;

        if SHELLS.contains(&name) {
            // `-c`, but also the combined forms agents write constantly (`-lc`,
            // `-euc`). The script is the next word and re-enters the lexer.
            let script = words[i + 1..].iter().position(|t| {
                let f = t.text.as_str();
                f.starts_with('-') && !f.starts_with("--") && f.contains('c')
            });
            match script.and_then(|k| words.get(i + 1 + k + 1)) {
                Some(script) => {
                    lex_into(&script.text, depth + 1, out);
                    return;
                }
                None => break,
            }
        }

        match name {
            "env" => {
                i += 1;
                skip_flags(words, &mut i, &["-u", "--unset", "-S", "--split-string"]);
            }
            "sudo" | "doas" => {
                i += 1;
                skip_flags(
                    words,
                    &mut i,
                    &["-u", "-g", "-p", "-C", "-U", "-r", "-t", "--user"],
                );
            }
            "time" | "command" | "builtin" => i += 1,
            "nice" => {
                i += 1;
                skip_flags(words, &mut i, &["-n", "--adjustment"]);
            }
            "xargs" => {
                i += 1;
                skip_flags(
                    words,
                    &mut i,
                    &[
                        "-a", "-n", "-I", "-i", "-P", "-d", "-E", "-e", "-s", "-L", "-l",
                    ],
                );
            }
            "timeout" => {
                i += 1;
                skip_flags(words, &mut i, &["-k", "-s", "--signal", "--kill-after"]);
                // The duration, which is positional and not a command.
                i = (i + 1).min(words.len());
            }
            _ if KEYWORDS.contains(&name) => i += 1,
            _ => break,
        }

        if i == before {
            break;
        }
        wrappers.push(name.to_string());
    }

    let Some(head) = words.get(i) else { return };

    // git carries its own options ahead of the subcommand, so `args.0` is only
    // a subcommand once they are out of the way. Without this, `git -C /repo
    // grep` and `git grep` look like different commands to every rule.
    let mut first_arg = i + 1;
    if basename(&head.text) == "git" {
        let mut j = first_arg;
        skip_flags(words, &mut j, GIT_VALUED);
        wrappers.extend(words[first_arg..j].iter().map(|w| w.text.clone()));
        first_arg = j;
    }

    let rest = &words[first_arg..];
    out.push(Segment {
        head: basename(&head.text).to_string(),
        args: rest.iter().map(|w| w.text.clone()).collect(),
        pipeline_start,
        depth,
        wrappers,
        head_span: head.span,
        arg_spans: rest.iter().map(|w| w.span).collect(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heads(cmd: &str) -> Vec<String> {
        lex(cmd).into_iter().map(|s| s.head).collect()
    }

    #[test]
    fn pipe_does_not_start_a_new_command() {
        let segs = lex("gh pr list | grep foo");
        assert_eq!(heads("gh pr list | grep foo"), ["gh", "grep"]);
        assert!(segs[0].pipeline_start);
        assert!(!segs[1].pipeline_start, "a piped grep is a filter");
    }

    #[test]
    fn control_operators_start_new_commands() {
        let segs = lex("cd /repo && grep -rn foo src/");
        assert_eq!(segs.len(), 2);
        assert!(segs[1].pipeline_start);
    }

    #[test]
    fn or_is_a_separator_not_a_pipe() {
        let segs = lex("false || grep foo x");
        assert!(segs[1].pipeline_start);
    }

    #[test]
    fn assignment_prefix_peels_but_a_flag_does_not() {
        assert_eq!(heads("GOFLAGS=-mod=mod grep -rn foo src/"), ["grep"]);
        let segs = lex(r#"grep -rn "func .*Conv" --include="*.go" pkg/domains"#);
        assert_eq!(segs[0].head, "grep");
        assert!(segs[0].args.contains(&"--include=*.go".to_string()));
    }

    #[test]
    fn shell_keywords_peel() {
        assert_eq!(
            heads("if grep -q foo file; then echo yes; fi"),
            ["grep", "echo"]
        );
        assert_eq!(
            heads("for f in *.go; do grep -n x $f; done"),
            ["for", "grep"]
        );
    }

    #[test]
    fn wrappers_peel() {
        assert_eq!(heads("sudo -u root timeout 30 grep foo x"), ["grep"]);
        assert_eq!(heads("env FOO=1 nice -n 10 rg bar"), ["rg"]);
        assert_eq!(heads("xargs -0 -I {} grep -n x {}"), ["grep"]);
        assert_eq!(heads("/usr/bin/time command find . -name x"), ["find"]);
    }

    #[test]
    fn git_options_do_not_displace_the_subcommand() {
        for command in [
            "git grep -n Conversation",
            "git -C /repo grep -n Conversation",
            "git -c core.pager=cat --no-pager grep -n Conversation",
            "git --git-dir /repo/.git grep -n Conversation",
        ] {
            let segs = lex(command);
            assert_eq!(segs[0].head, "git", "{command}");
            assert_eq!(segs[0].args[0], "grep", "{command}");
        }
        // The repo `-C` names is not an argument to the search, so it must not
        // read as an unindexed path either.
        let segs = lex("git -C /repo grep -n x");
        assert!(!segs[0].args.contains(&"/repo".to_string()));
    }

    #[test]
    fn bash_dash_c_recurses() {
        let segs = lex(r#"bash -c 'grep -rn -i "virtual" src/Chat.tsx | head -20'"#);
        assert_eq!(
            segs.iter().map(|s| s.head.as_str()).collect::<Vec<_>>(),
            ["grep", "head"]
        );
        assert_eq!(segs[0].depth, 1);
        assert!(segs[0].pipeline_start);
        assert!(segs[0].head_span.is_none(), "nested text has no outer span");
    }

    #[test]
    fn combined_shell_flags_recurse() {
        assert_eq!(heads("bash -lc 'rg foo src'"), ["rg"]);
    }

    #[test]
    fn redirect_targets_are_not_arguments() {
        let segs = lex(r#"grep -rn foo pkg 2>/dev/null | head"#);
        assert_eq!(segs[0].args, ["-rn", "foo", "pkg"]);
    }

    #[test]
    fn command_substitution_is_lexed() {
        assert_eq!(heads("echo $(grep -rn foo src)"), ["echo", "grep"]);
    }

    #[test]
    fn spans_cover_the_head_token() {
        let cmd = "cd x && rm -rf build";
        let segs = lex(cmd);
        let span = segs[1].head_span.expect("top-level span");
        assert_eq!(&cmd[span.start..span.end], "rm");
    }
}

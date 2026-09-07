use std::fs;

use crate::sandbox::{cli, decision, is_denied, Sandbox};

#[test]
fn a_repo_overlay_disables_an_inherited_rule() {
    let sandbox = Sandbox::new("overlay");
    assert!(is_denied(&decision(&sandbox, "grep -rn foo src")));

    sandbox.write(".steer.toml", "disable = [\"fff-over-grep\"]\n");
    assert!(!is_denied(&decision(&sandbox, "grep -rn foo src")));
}

#[test]
fn an_overlay_rule_is_appended() {
    let sandbox = Sandbox::new("append");
    sandbox.write(
        ".steer.toml",
        r#"
[[rules]]
name = "no-curl"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["curl"] }

[rules.action]
kind = "deny"
message = "use the WebFetch tool"
"#,
    );
    let value = decision(&sandbox, "curl https://example.com");
    assert!(is_denied(&value));
    assert_eq!(
        value.pointer("/hookSpecificOutput/permissionDecisionReason"),
        Some(&serde_json::json!("use the WebFetch tool"))
    );
}

// Naming every built-in in `disable` is complete only until the next one ships,
// so starting from none of them is its own setting — and the report has to show
// what it turned off rather than an empty stack.
#[test]
fn builtins_can_be_switched_off_wholesale() {
    let sandbox = Sandbox::new("nobuiltins");
    sandbox.write_global(
        r#"
builtins = false

[[rules]]
name = "mine"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }
[rules.action]
kind = "deny"
message = "not against prod"
[rules.test]
fires = ["psql -h prod"]
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("ok        1 rules"), "{out}");
    assert!(
        out.contains("turned off by `builtins = false`"),
        "listed, and said to be off: {out}"
    );

    assert!(!is_denied(&decision(&sandbox, "grep -rn foo src")), "{out}");
    assert!(is_denied(&decision(&sandbox, "psql -h prod")), "{out}");
}

// `--config` names the whole ruleset rather than a fourth layer on the stack.
// The built-ins and the global config are not switched off here — they never
// load — so the report has to read as a replacement rather than as something
// with a stack behind it.
#[test]
fn a_named_config_stands_in_for_the_whole_stack() {
    let sandbox = Sandbox::new("onlyconfig");
    sandbox.write_global(
        r#"
[[rules]]
name = "from-the-global"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }
[rules.action]
kind = "deny"
message = "not against prod"
"#,
    );
    // `builtins = false` has nothing left to switch off, so it says nothing.
    let body = r#"
builtins = false

[[rules]]
name = "only-this"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }
[rules.action]
kind = "deny"
message = "Use the Edit tool."
[rules.test]
fires = ["ruby script.rb"]
ignores = ["rake build"]
"#;
    let only = sandbox.dir.join("only.toml");
    fs::write(&only, body).expect("write named config");
    let path = only.display().to_string();

    let (out, code) = cli(&sandbox, &["validate", "--config", &path]);
    assert_eq!(code, 0, "the file's own examples still run: {out}");
    assert!(out.contains(&format!("source    {path}")), "{out}");
    assert!(out.contains("ok        1 rules"), "{out}");
    assert!(!out.contains("built-in"), "nothing under it: {out}");
    assert!(!out.contains("from-the-global"), "nothing over it: {out}");
    assert!(!out.contains("turned off"), "nothing to turn off: {out}");

    let (out, code) = cli(&sandbox, &["check", "--config", &path, "ruby script.rb"]);
    assert_eq!(code, 1, "{out}");
    let (out, code) = cli(&sandbox, &["check", "--config", &path, "grep -rn foo src"]);
    assert_eq!(
        code, 0,
        "gone from the decision, not just the report: {out}"
    );

    // A `disable` is answered by this file alone, so naming an inherited rule
    // is the same unresolved name it has always been.
    fs::write(&only, format!("disable = [\"fff-over-grep\"]\n{body}")).expect("rewrite config");
    let (out, code) = cli(&sandbox, &["validate", "--config", &path]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("disable names `fff-over-grep`, which no rule defines"),
        "{out}"
    );

    // A ruleset that is not there is not a reason to load the one it replaced.
    let (out, code) = cli(
        &sandbox,
        &["validate", "--config", "/nonexistent/steer.toml"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("/nonexistent/steer.toml"), "{out}");
}

// An example that stops being true has to fail, or it is just a comment.
#[test]
fn validate_runs_the_examples_a_rule_declares() {
    let sandbox = Sandbox::new("examples");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-prod-psql"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }
[rules.action]
kind = "deny"
message = "x"
[rules.test]
fires = ["psql -h prod"]
ignores = ["psql -h replica", "ls -la"]
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "a wrong example is a problem: {out}");
    assert!(
        out.contains("`ignores` example \"psql -h replica\" fires `no-prod-psql`"),
        "{out}"
    );
    assert!(
        out.contains("config.toml:13:12"),
        "expected the example's own line and column, got {out}"
    );
    assert!(!out.contains("\"psql -h prod\""), "{out}");
}

// `fires` only asserts that a rewrite happened. What it produced was displayed
// and unchecked, so a splice that started cutting the wrong span stayed silent.
#[test]
fn validate_checks_what_a_rewrite_produces() {
    let sandbox = Sandbox::new("rewriteexamples");
    sandbox.write_global(
        r#"
[[rules]]
name = "trash-over-rm"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["rm"] }
[rules.action]
kind = "rewrite"
replace_head = "trash"
drop_args = ["-rf"]
[rules.test]
rewrites = { "rm -rf dist" = "trash dist", "cd build && rm -rf out" = "cd build && rm out" }
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("\"cd build && trash out\""),
        "expected the produced command: {out}"
    );
    // `trash` is absent from the sandbox PATH, so this also pins that the
    // assertion survives a rewrite the engine would hold back at runtime.
    assert!(!out.contains("\"trash dist\""), "{out}");
}

#[test]
fn a_rewrites_example_on_a_rule_that_never_rewrites_is_a_problem() {
    let sandbox = Sandbox::new("rewritewrongkind");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-prod-psql"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }
[rules.action]
kind = "deny"
message = "x"
[rules.test]
rewrites = { "psql -h prod" = "psql -h replica" }
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("no-prod-psql"), "{out}");
    assert!(out.contains("rewrite"), "{out}");
}

#[test]
fn validate_accepts_the_built_ins_alone() {
    let sandbox = Sandbox::new("validok");
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("ok"), "{out}");
}

// A rule count cannot answer which definition of a name is the live one, which
// is the question a stack of three sources raises.
#[test]
fn validate_shows_what_the_stack_did_to_each_rule() {
    let sandbox = Sandbox::new("validtree");
    sandbox.write_global("disable = [\"edit-over-python\"]\n");
    sandbox.write(
        ".steer.toml",
        r#"
[[rules]]
name = "trash-over-rm"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["rm"] }
[rules.action]
kind = "context"
message = "x"
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("disabled by"), "{out}");
    assert!(out.contains("replaced by"), "{out}");
    assert!(
        out.contains("match   any parsed.segments  head=rm"),
        "conditions: {out}"
    );
    // Piped output carries no escapes, so it stays greppable.
    assert!(!out.contains('\u{1b}'), "{out}");
    assert!(out.contains("ok        7 rules"), "{out}");
}

#[test]
fn validate_reports_the_file_and_line_of_each_problem() {
    let sandbox = Sandbox::new("validbad");
    sandbox.write_global(
        r#"disable = ["no-such-rule"]

[[rules]]
name = "dup"
[[rules.match]]
path = { glob = ["["] }
[rules.action]
kind = "deny"
message = "x"

[[rules]]
name = "dup"
[[rules.match]]
path = { any_of = ["y"] }
[rules.action]
kind = "deny"
message = "x"
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("no-such-rule"), "{out}");
    assert!(out.contains("duplicate rule name `dup`"), "{out}");
    assert!(
        out.contains("config.toml:12"),
        "expected file:line, got {out}"
    );
}

// The vocabulary rename left `tool = "Bash"` parsing cleanly and matching
// nothing, and a rule declaring no examples had nothing left to fail on.
#[test]
fn an_unmatchable_tool_gate_is_a_problem() {
    let sandbox = Sandbox::new("deadgates");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-prod-psql"
tool = "Bash"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }
[rules.action]
kind = "deny"
message = "x"

[[rules]]
name = "no-lockfile-edits"
[[rules.match]]
tool_name = { any_of = ["Edit", "write", "NotebookEdit"] }
path = { glob = ["*/Cargo.lock"] }
[rules.action]
kind = "deny"
message = "x"
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("`tool = \"Bash\"` can never match; ingest renames it to `shell`"),
        "{out}"
    );
    assert!(
        out.contains("`\"Edit\" in tool_name` can never match; ingest renames it to `edit`"),
        "{out}"
    );
    assert!(out.contains("config.toml:4:8"), "expected file:line: {out}");
    // Two, not four: `write` maps to itself and no harness maps `NotebookEdit`
    // at all, which is how an MCP tool stays addressable.
    assert_eq!(out.matches("can never match").count(), 2, "{out}");
}

// The hazard the examples were carrying: `secrets.toml` and `workflow.toml`
// both matched on `file_path`, which ingest renames to `path` before any rule
// sees it.
#[test]
fn an_unmatchable_field_is_a_problem() {
    let sandbox = Sandbox::new("deadfields");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-lockfile-edits"
tool = "edit"
[[rules.match]]
file_path = { glob = ["*/Cargo.lock"] }
[rules.action]
kind = "deny"
message = "x"

[[rules]]
name = "anything-but-the-lockfile"
tool = "edit"
[[rules.match]]
file_path = { none_glob = ["*/Cargo.lock"] }
[rules.action]
kind = "deny"
message = "x"
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("`file_path` can never match; ingest renames it to `path`"),
        "{out}"
    );
    assert!(out.contains("config.toml:6:1"), "expected file:line: {out}");
    // One, not two: a `none_glob` against a field nothing carries excludes
    // nothing, which widens the second rule rather than killing it.
    assert_eq!(out.matches("can never match").count(), 1, "{out}");
}

// A rule that reaches a harness in a weaker form, or not at all, is the failure
// this report exists to catch — so every harness gets a verdict rather than an
// omission.
#[test]
fn validate_prints_a_per_harness_verdict() {
    let sandbox = Sandbox::new("verdicts");
    sandbox.write_global(
        r#"
builtins = false

[[rules]]
name = "trash-over-rm"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["rm"] }
[rules.action]
kind = "rewrite"
replace_head = "trash"

[[rules]]
name = "claude-only"
tool = "shell"
agents = ["claude"]
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }
[rules.action]
kind = "deny"
message = "x"

[[rules]]
name = "spoken-to-claude"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["perl"] }
[rules.action]
kind = "deny"
[rules.action.message]
claude = "Use the Edit tool."

[[rules]]
name = "note-before-cargo"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["cargo"] }
[rules.action]
kind = "context"
message = "a note"
"#,
    );

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");

    // Keyed by rule name and pinned to the verdict rather than to the roster or
    // the count, both of which would make adding a harness a test edit — the
    // per-harness cost the descriptor exists to remove.
    let line = |needle: &str| {
        out.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_default()
    };

    assert!(
        out.contains("codex, cline, goose, windsurf, antigravity: deny carrying the command"),
        "{out}"
    );
    assert!(line("claude-only").contains("· claude ·"), "{out}");
    assert!(
        line("claude-only").contains("dropped, not in `agents`"),
        "{out}"
    );
    // The group it was dropped for is counted, not spelled: naming fifteen
    // harnesses is what buries the one that matters.
    assert!(!line("claude-only").contains("windsurf"), "{out}");
    assert!(
        line("spoken-to-claude").contains("dropped, the message says nothing to it"),
        "{out}"
    );
    assert!(
        line("note-before-cargo").contains("dropped, it takes no context before a call"),
        "{out}"
    );
}

#[test]
fn validate_rejects_an_unknown_field() {
    let sandbox = Sandbox::new("validunknown");
    sandbox.write_global(
        r#"
[[rules]]
name = "typo"
tolo = "shell"
[[rules.match]]
path = { any_of = ["y"] }
[rules.action]
kind = "deny"
message = "x"
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("tolo"), "{out}");
}

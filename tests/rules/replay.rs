// `replay` and `suggest`, which read the log back against today's rules.

use crate::sandbox::{cli, Sandbox};

// A transition between two outcome names is the engine's vocabulary, not a
// consequence. A log also outlives the rules that answered it, so the age of a
// difference decides whether it is about a rule just written.
#[test]
fn replay_reports_the_consequence_and_the_age_of_a_difference() {
    let sandbox = Sandbox::new("replaydrift");
    sandbox.write_log(&[serde_json::json!({
        "ts_ms": 1_000,
        "outcome": "deny",
        "rules": ["fff-over-grep"],
        "tool_name": "shell",
        "session_id": "s1",
        "cwd": sandbox.work().display().to_string(),
        // A search after a pipe is a filter, so today's rules allow it.
        "tool_input": { "command": "gh pr list | grep foo" },
    })]);

    let (out, code) = cli(&sandbox, &["replay"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("nothing is written"), "{out}");
    assert!(
        out.contains("would now go through"),
        "the consequence, not the transition: {out}"
    );
    assert!(
        out.contains("fff-over-grep  gh pr list | grep foo"),
        "the rule that stopped catching it, beside the call: {out}"
    );
    assert!(
        out.contains("none from the last day"),
        "an old difference is not about a rule just written: {out}"
    );

    let (out, code) = cli(&sandbox, &["replay", "--since", "30m"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("none would land differently"), "{out}");

    let (out, code) = cli(&sandbox, &["replay", "--since", "5x"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("unknown unit `x`"), "{out}");
}

// A draft is a recommendation whatever the comments around it say, so an unsure
// tool has to produce no draft at all, and say why outside a file nobody has
// pasted yet.
#[test]
fn draft_declines_when_the_rule_does_not_know_the_command_that_followed() {
    let sandbox = Sandbox::new("weak");
    sandbox.write_log(&[
        sandbox.entry(
            1_000,
            "deny",
            serde_json::json!(["fff-over-grep"]),
            "grep -n ts:security Taskfile.yml",
        ),
        sandbox.entry(9_000, "allow", serde_json::json!([]), "task ts:security"),
    ]);

    let (out, code) = cli(&sandbox, &["suggest", "--draft", "fff-over-grep"]);
    assert_eq!(
        code, 2,
        "no draft is an error exit, not empty output: {out}"
    );
    assert!(!out.contains("[[rules]]"), "nothing pasteable: {out}");
    assert!(out.contains("says nothing about `task`"), "{out}");
    assert!(out.contains("steer suggest --draft task"), "{out}");

    // The report counts a weak pair rather than printing it: it is a question,
    // and there are always more questions than findings.
    let (out, _) = cli(&sandbox, &["suggest"]);
    assert!(out.contains("0 fixes"), "nothing to act on: {out}");
    assert!(out.contains("weak      1 pair where"), "{out}");

    let (out, _) = cli(&sandbox, &["suggest", "--all"]);
    assert!(
        out.contains("signal  the rule says nothing about `task`"),
        "{out}"
    );
}

// A log outlives the rules read against it, so the same pair keeps coming back
// long after the edit that closed it.
#[test]
fn suggest_sorts_a_closed_pair_out_of_the_fixes() {
    let sandbox = Sandbox::new("sorted");
    let searches = serde_json::json!(["fff-over-grep"]);
    let pagers = serde_json::json!(["read-over-shell-pager"]);
    let allowed =
        |ts_ms: u64, command: &str| sandbox.entry(ts_ms, "allow", serde_json::json!([]), command);
    sandbox.write_log(&[
        // Earliest in the log and weak: the rule was refused and something else
        // entirely ran next. Drafting reaches for the finding, not for this.
        sandbox.entry(
            100,
            "deny",
            searches.clone(),
            "grep -n ts:security Taskfile.yml",
        ),
        allowed(200, "task ts:security"),
        // Four of one thing: a `git grep` outside the tree. That block declares
        // no escapes of its own, so this is a hole rather than a decision the
        // rule already made.
        sandbox.entry(1_000, "deny", searches.clone(), "git grep -n foo src"),
        allowed(5_000, "git grep -n foo /etc/hosts"),
        sandbox.entry(10_000, "deny", searches.clone(), "git grep -n bar src"),
        allowed(12_000, "git grep -n bar /usr/local/include"),
        sandbox.entry(20_000, "deny", searches.clone(), "git grep -n baz docs"),
        allowed(22_000, "git grep -n baz /opt/homebrew/share"),
        sandbox.entry(30_000, "deny", searches, "git grep -n qux dist"),
        allowed(32_000, "git grep -n qux /var/log"),
        sandbox.entry(70_000, "deny", pagers, "cat -n src/main.rs"),
        // The pager rule dropped its workspace guard, so today this is a deny
        // and the pair is an edit already made.
        allowed(72_000, "cat /tmp/notes.md"),
    ]);

    let (out, code) = cli(&sandbox, &["suggest"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("fix       fff-over-grep"),
        "the open pair leads, under the rule an edit goes to: {out}"
    );
    assert!(
        out.contains("in_workspace"),
        "named by the condition that held the rule open: {out}"
    );
    assert!(
        !out.contains("fix       read-over-shell-pager"),
        "a pair today's rules answer is not a finding: {out}"
    );
    assert!(out.contains("closed    1 pair"), "{out}");
    assert!(out.contains("1 fix, 1 closed"), "{out}");
    // Four pairs are one edit, so the group is the finding and the evidence
    // under it stops at enough to judge the pairing on.
    assert!(out.contains("4 pairs"), "{out}");
    assert!(out.contains("1 more like it"), "{out}");
    assert!(!out.contains("/var/log"), "{out}");
    // One rule can be open through two conditions, and those are two edits, so
    // the command a fix line prints has to say which.
    assert!(out.contains("--draft fff-over-grep:in_workspace"), "{out}");

    let (out, _) = cli(&sandbox, &["suggest", "--all"]);
    assert!(out.contains("/var/log"), "asking gets the rest: {out}");

    // The command a fix line prints has to land on that fix. Reading the log
    // in time order instead reaches the weak pair and declines over a finding
    // the report never showed.
    for name in ["fff-over-grep", "fff-over-grep:in_workspace"] {
        let (out, code) = cli(&sandbox, &["suggest", "--draft", name]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("[[rules]]"), "{out}");
        assert!(!out.contains("says nothing about `task`"), "{out}");
        // The block is the one this call missed with `in_workspace` dropped, so
        // the subcommand that pins the rule to `git grep` survives. A block
        // drafted from the command alone would have caught every `git`.
        assert!(
            out.contains("# + \"args.0\" = { any_of = [\"grep\"] }"),
            "{out}"
        );
    }

    // The narrowed block closes the escape without touching what the rule
    // declares it must leave alone.
    let (draft, _) = cli(&sandbox, &["suggest", "--draft", "fff-over-grep"]);
    sandbox.write_global(&draft);
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "the narrowed draft holds its own examples: {out}");
    sandbox.write_global("");

    let (out, code) = cli(&sandbox, &["suggest", "--apply"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("apply     fff-over-grep"), "{out}");
    assert!(out.contains("4 declared"), "{out}");

    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "the declarations have to hold: {out}");
    let (out, _) = cli(&sandbox, &["suggest"]);
    assert!(out.contains("0 fixes"), "the finding is answered: {out}");
    assert!(out.contains("design    4 pairs"), "{out}");

    // An amendment, not a copy of the rule: a copy pins the built-in at the
    // text pasted.
    let written = sandbox.global_text();
    assert!(written.contains("[[amend]]"), "{written}");
    assert!(!written.contains("[[rules.match]]"), "{written}");
    assert!(written.lines().count() < 15, "{written}");
}

// A draft is a paste, so the test is the paste. The escape here is a heredoc,
// the shape that put a document into the comment block and left every line
// after the first as bare TOML.
#[test]
fn a_draft_written_to_a_config_is_a_config() {
    let sandbox = Sandbox::new("pasted");
    sandbox.write_log(&[
        sandbox.entry(
            1_000,
            "deny",
            serde_json::json!(["read-over-shell-pager"]),
            "cat src/main.rs",
        ),
        sandbox.entry(
            3_000,
            "allow",
            serde_json::json!([]),
            "cat > /tmp/pr.md <<'BODY'\n## Ticket\n\n* ENG-1\n\nprose that is not toml\nBODY",
        ),
    ]);

    let (draft, code) = cli(&sandbox, &["suggest", "--draft", "read-over-shell-pager"]);
    assert_eq!(code, 0, "{draft}");
    // The change, spelled out above the whole rule it is buried in.
    assert!(draft.contains("# + [[rules.match]]"), "{draft}");
    // The block it adds is the one that missed with the `matches` that held it
    // open dropped, so the `-f` exclusion beside it survives.
    assert!(
        draft.contains("# + head = { any_of = [\"cat\", \"head\", \"tail\", \"bat\"] }"),
        "{draft}"
    );
    assert!(
        draft.contains("# + args = { none_of = [\"-f\", \"--follow\"] }"),
        "{draft}"
    );
    assert!(draft.contains("# + fires += cat > /tmp/pr.md"), "{draft}");
    // The example is the command, not the document it was carrying: a heredoc
    // body is stripped before any rule sees it, so shipping it would put a page
    // of somebody's prose in a config to no end.
    assert!(draft.contains("\"cat > /tmp/pr.md <<'BODY'\""), "{draft}");
    assert!(!draft.contains("prose that is not toml"), "{draft}");

    sandbox.write_global(&draft);
    let (out, _) = cli(&sandbox, &["validate"]);
    assert!(!out.contains("unparsed"), "{out}");
    assert!(!out.contains("TOML parse error"), "{out}");
    // `cat > out <<EOF` is an escape the pager rule declares, and even the
    // narrowed block reaches it: dropping the `matches` that held the escape
    // open is what the escape was. `validate` naming the contradiction is the
    // report saying closing was the wrong answer for this one.
    assert!(
        out.contains("`ignores` example \"cat > out.md <<'EOF'\" fires `read-over-shell-pager`"),
        "{out}"
    );

    sandbox.write_global("");
    let (out, code) = cli(&sandbox, &["suggest", "--apply"]);
    assert_eq!(code, 0, "{out}");
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "the answer this finding wanted: {out}");
    let (out, _) = cli(&sandbox, &["suggest"]);
    assert!(out.contains("0 fixes"), "{out}");
    assert!(out.contains("design    1 pair"), "{out}");
}

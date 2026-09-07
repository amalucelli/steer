use crate::sandbox::{decision, is_denied, updated_command, Sandbox};

#[test]
fn rewrite_replaces_the_head_and_drops_recursive_flags() {
    let sandbox = Sandbox::new("rewrite");
    sandbox.stub_binary("trash");

    let value = decision(&sandbox, "cd build && rm -rf dist");
    assert_eq!(updated_command(&value), Some("cd build && trash dist"));
    // Force-approving would route the rewritten delete around the permission
    // classifier, so no decision is emitted alongside the new input.
    assert!(value
        .pointer("/hookSpecificOutput/permissionDecision")
        .is_none());
}

#[test]
fn rewrite_falls_through_when_the_replacement_is_missing() {
    let sandbox = Sandbox::new("nopath");
    let value = decision(&sandbox, "rm -rf dist");
    assert_eq!(value, serde_json::Value::Null, "expected a clean allow");
}

#[test]
fn a_deny_outranks_a_rewrite() {
    let sandbox = Sandbox::new("strongest");
    sandbox.stub_binary("trash");
    let value = decision(&sandbox, "grep -rn foo src && rm -rf dist");
    assert!(is_denied(&value));
    assert!(value.pointer("/hookSpecificOutput/updatedInput").is_none());
}

// A rewrite that only injects a flag, which is what the `--no-ext-diff` case
// needs: no head to replace, so nothing for the PATH gate to look up either.
const ADD_ARGS: &str = r#"
[[rules]]
name = "git-diff-no-ext-diff"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["git"] }
"args.0" = { any_of = ["diff"] }
args = { none_of = ["--no-ext-diff"] }

[rules.action]
kind = "rewrite"
add_args = ["--no-ext-diff"]
"#;

fn rewritten(sandbox: &Sandbox, command: &str) -> String {
    updated_command(&decision(sandbox, command))
        .unwrap_or_else(|| panic!("no rewrite for {command:?}"))
        .to_string()
}

// The flag lands after the subcommand rather than after the head: `git` peels
// its own options during enrichment, and `git --no-ext-diff diff` is the wrong
// spelling. Redirection targets are stripped from `args`, so they are not the
// last token even when they are the last thing written.
#[test]
fn add_args_appends_after_the_last_operand() {
    let sandbox = Sandbox::new("addargs");
    sandbox.write_global(ADD_ARGS);

    assert_eq!(rewritten(&sandbox, "git diff"), "git diff --no-ext-diff");
    assert_eq!(
        rewritten(&sandbox, "git diff --stat"),
        "git diff --stat --no-ext-diff"
    );
    assert_eq!(
        rewritten(&sandbox, "git -C /repo diff"),
        "git -C /repo diff --no-ext-diff"
    );
    assert_eq!(
        rewritten(&sandbox, "git diff > out.txt"),
        "git diff --no-ext-diff > out.txt"
    );
}

// Everything after `--` is an operand by getopt convention, so a flag appended
// past it is read as a pathspec rather than as a flag.
#[test]
fn add_args_lands_before_the_operand_separator() {
    let sandbox = Sandbox::new("addargssep");
    sandbox.write_global(ADD_ARGS);

    assert_eq!(
        rewritten(&sandbox, "git diff HEAD~1 -- src/"),
        "git diff HEAD~1 --no-ext-diff -- src/"
    );
}

// The rule's own `none_of` is what stops a second pass, so the engine needs no
// idempotence of its own.
#[test]
fn add_args_leaves_a_command_that_already_carries_the_flag() {
    let sandbox = Sandbox::new("addargsidem");
    sandbox.write_global(ADD_ARGS);

    assert_eq!(
        decision(&sandbox, "git diff --no-ext-diff"),
        serde_json::Value::Null,
        "expected a clean allow"
    );
}

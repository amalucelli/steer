use crate::sandbox::{bash_payload, decision, is_denied, note, updated_command, Sandbox};

// A non-Bash payload has no `parsed` object; the same conditions reach it.
#[test]
fn a_rule_matches_a_non_bash_tool() {
    let sandbox = Sandbox::new("nonbash");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-lockfile-edits"
tool = "edit"

[[rules.match]]
path = { glob = ["*/Cargo.lock"] }

[rules.action]
kind = "deny"
message = "regenerate the lockfile with cargo"
"#,
    );
    let payload = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": "/repo/Cargo.lock", "old_string": "a", "new_string": "b" },
    })
    .to_string();
    assert!(is_denied(&sandbox.hook("PreToolUse", &payload)));
}

// `NotebookEdit` keeps its own name, since no other harness has the tool — but
// the file it acts on still has to reach a rule as `path`, or every rule about
// a file silently skips notebooks.
#[test]
fn a_notebook_edit_reaches_a_rule_as_a_path() {
    let sandbox = Sandbox::new("notebook");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-secret-notebooks"

[[rules.match]]
tool_name = { any_of = ["edit", "NotebookEdit"] }
path = { glob = ["*/secret*"] }

[rules.action]
kind = "deny"
message = "that notebook holds a credential"
"#,
    );
    let payload = serde_json::json!({
        "tool_name": "NotebookEdit",
        "tool_input": { "notebook_path": "/repo/secret.ipynb", "new_source": "x" },
    })
    .to_string();
    assert!(is_denied(&sandbox.hook("PreToolUse", &payload)));
}

#[test]
fn post_tool_use_only_injects_context() {
    let sandbox = Sandbox::new("post");
    sandbox.write_global(
        r#"
[[rules]]
name = "note-tests"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["cargo"] }
"args.0" = { any_of = ["test"] }

[rules.action]
kind = "context"
message = "failures here are often stale fixtures"
"#,
    );
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cargo test" },
    })
    .to_string();
    let value = sandbox.hook("PostToolUse", &payload);
    assert_eq!(
        value.pointer("/hookSpecificOutput/additionalContext"),
        Some(&serde_json::json!("failures here are often stale fixtures"))
    );

    // A deny rule is inert after the call already ran.
    let grep = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "grep -rn foo src" },
    })
    .to_string();
    assert_eq!(sandbox.hook("PostToolUse", &grep), serde_json::Value::Null);
}

#[test]
fn every_deny_is_logged_with_its_rule_and_agent_type() {
    let sandbox = Sandbox::new("log");
    let payload = serde_json::json!({
        "session_id": "s1",
        "agent_type": "Explore",
        "cwd": sandbox.work().display().to_string(),
        "tool_name": "Bash",
        "tool_input": { "command": "grep -rn foo src" },
    })
    .to_string();
    sandbox.hook("PreToolUse", &payload);

    let lines = sandbox.log_lines();
    assert_eq!(lines.len(), 1);
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("json line");
    assert_eq!(entry["outcome"], "deny");
    assert_eq!(entry["rules"], serde_json::json!(["fff-over-grep"]));
    assert_eq!(entry["agent_type"], "Explore");
    assert_eq!(entry["harness"], "claude");
    assert_eq!(entry["tool_input"]["command"], "grep -rn foo src");
    // The harness sent `Bash`; everything past the boundary speaks the
    // canonical vocabulary.
    assert_eq!(entry["tool_name"], "shell");
}

// A deny is only half the story: the command that ran instead is what names the
// spelling a rule missed, so an allowed Bash call is logged too. Other tools
// stay out, which keeps a Write payload's file contents off disk.
#[test]
fn allowed_bash_calls_are_logged_and_other_tools_are_not() {
    let sandbox = Sandbox::new("allowlog");

    decision(&sandbox, "gh pr list | grep foo");
    let lines = sandbox.log_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("json line");
    assert_eq!(entry["outcome"], "allow");
    assert_eq!(entry["rules"], serde_json::json!([]));
    assert_eq!(entry["tool_input"]["command"], "gh pr list | grep foo");

    let payload = serde_json::json!({
        "session_id": "test",
        "tool_name": "Write",
        "tool_input": { "file_path": "notes.md", "content": "secret" },
        "cwd": sandbox.work().display().to_string(),
    })
    .to_string();
    sandbox.hook("PreToolUse", &payload);
    assert_eq!(sandbox.log_lines().len(), 1, "a Write allow must not log");
}

// A gate ingest renames is a rule that reads as live and matches nothing, and
// `validate` exits 1 on it. Here it can only be said: a config error that
// blocked every tool call would block the ones needed to fix it.
#[test]
fn a_dead_tool_gate_is_reported_and_the_call_still_runs() {
    let sandbox = Sandbox::new("deadgate");
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
message = "not against prod"
"#,
    );

    let value = decision(&sandbox, "psql -h prod");
    assert!(!is_denied(&value), "{value}");
    let said = note(&value);
    assert!(said.contains("no-prod-psql"), "{said}");
    assert!(said.contains("`shell`"), "{said}");

    let value = decision(&sandbox, "grep -rn foo src");
    assert!(is_denied(&value), "{value}");
    assert!(!note(&value).is_empty(), "{value}");

    // A rewrite speaks through the same field, so the note joins it rather than
    // replacing what the rule had to say.
    sandbox.stub_binary("trash");
    let value = decision(&sandbox, "rm -rf dist");
    assert_eq!(updated_command(&value), Some("trash dist"));
    let said = note(&value);
    assert!(said.contains("stays recoverable"), "{said}");
    assert!(said.contains("no-prod-psql"), "{said}");
}

#[test]
fn a_dead_field_is_reported_and_the_call_still_runs() {
    let sandbox = Sandbox::new("deadfield");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-lockfile-edits"
tool = "edit"

[[rules.match]]
file_path = { glob = ["*/Cargo.lock"] }

[rules.action]
kind = "deny"
message = "regenerate the lockfile with cargo"
"#,
    );
    let payload = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": "/repo/Cargo.lock", "old_string": "a", "new_string": "b" },
    })
    .to_string();

    let value = sandbox.hook("PreToolUse", &payload);
    assert!(!is_denied(&value), "{value}");
    let said = note(&value);
    assert!(said.contains("no-lockfile-edits"), "{said}");
    assert!(said.contains("`path`"), "{said}");
}

#[test]
fn broken_input_and_broken_config_still_allow() {
    let sandbox = Sandbox::new("failopen");

    for stdin in ["", "not json at all", "{\"tool_name\": 5}"] {
        let stdout = sandbox.run(&["hook", "--event", "PreToolUse"], stdin);
        assert!(!stdout.contains("\"deny\""), "denied on {stdin:?}");
    }

    sandbox.write_global("this is not = valid toml [[[\n");
    let stdout = sandbox.run(
        &["hook", "--event", "PreToolUse", "--agent", "claude"],
        &bash_payload("grep -rn foo src", Some(&sandbox.work())),
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(!is_denied(&value));
    let message = note(&value);
    assert!(message.contains("steer"), "{message}");
}

#[test]
fn an_unknown_event_allows_rather_than_blocks() {
    let sandbox = Sandbox::new("badevent");
    let stdout = sandbox.run(
        &["hook", "--event", "Nonsense"],
        &bash_payload("grep -rn x src", Some(&sandbox.work())),
    );
    assert!(stdout.contains("systemMessage"), "{stdout}");
    assert!(!stdout.contains("\"deny\""));
    // The envelope lands in the model's context, so it carries what the caller
    // can act on and none of the terminal furniture around it.
    assert!(stdout.contains("PreToolUse, PostToolUse"), "{stdout}");
    assert!(!stdout.contains("For more information"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'), "{stdout}");

    let stdout = sandbox.run(
        &["hook", "--bogus", "--event", "PreToolUse"],
        &bash_payload("grep -rn x src", Some(&sandbox.work())),
    );
    assert!(stdout.contains("--bogus"), "{stdout}");
    assert!(!stdout.contains("\"deny\""), "{stdout}");
}

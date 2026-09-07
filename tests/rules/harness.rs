// A harness is a descriptor plus a fixture row, so everything that varies
// between them is tested here rather than beside the rules that reach it.

use crate::sandbox::{bash_payload, cli, is_denied, note, reason, Sandbox};

// Rules of the fixture table's own, so a row pins a harness's envelope rather
// than the current wording of a built-in message.
const FIXTURE_RULES: &str = r#"
builtins = false

[[rules]]
name = "fixture-deny"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["curl"] }
[rules.action]
kind = "deny"
message = "no network"

[[rules]]
name = "fixture-rewrite"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["rm"] }
[rules.action]
kind = "rewrite"
replace_head = "trash"
drop_args = ["-rf"]
message = "deletes stay recoverable"

[[rules]]
name = "fixture-context"
tool = "shell"
[[rules.match]]
any = "parsed.segments"
head = { any_of = ["cargo"] }
[rules.action]
kind = "context"
message = "a note before the call"

[[rules]]
name = "fixture-edit"
tool = "edit"
[[rules.match]]
path = { glob = ["*/Cargo.lock"] }
[rules.action]
kind = "deny"
message = "regenerate the lockfile"
"#;

// A test of its own would let a new harness quietly skip whatever its author did
// not think to assert, and none of them can be tried against a live install to
// find out.
#[test]
fn each_harness_answers_the_payload_its_docs_publish() {
    let sandbox = Sandbox::new("harnesses");
    sandbox.stub_binary("trash");
    sandbox.write_global(FIXTURE_RULES);
    let cwd = sandbox.work().display().to_string();

    let claude = |tool_name: &str, tool_input: serde_json::Value| {
        serde_json::json!({
            "session_id": "abc",
            "transcript_path": "/home/u/.claude/projects/-repo/session.jsonl",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        })
    };
    let codex = |command: &str| {
        serde_json::json!({
            "session_id": "abc",
            "turn_id": "t1",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    };
    // Qwen Code's request is Claude Code's, `tool_use_id` included, and its
    // tools are Gemini CLI's.
    let qwen = |tool_name: &str, tool_input: serde_json::Value| {
        serde_json::json!({
            "session_id": "abc",
            "transcript_path": "/home/u/.qwen/tmp/session.json",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "call_1",
        })
    };
    let continue_dev = |command: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "tool_use_id": "call_1",
            "session_id": "abc",
            "cwd": cwd,
        })
    };
    // Junie publishes the request with these three fields and nothing else.
    let junie = |command: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    };
    // Gemini CLI fires `BeforeTool`, and steer is registered under that key
    // with `--event PreToolUse` — nothing it emits carries an event name.
    let gemini = |command: &str| {
        serde_json::json!({
            "session_id": "abc",
            "transcript_path": "/home/u/.gemini/tmp/session.json",
            "cwd": cwd,
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-09-07T10:00:00Z",
            "tool_name": "run_shell_command",
            "tool_input": { "command": command },
        })
    };
    // Cursor's request is snake_case like Claude Code's; only the tool names and
    // the response differ.
    let cursor = |tool_name: &str, tool_input: serde_json::Value| {
        serde_json::json!({
            "conversation_id": "abc",
            "generation_id": "gen_1",
            "hook_event_name": "preToolUse",
            "workspace_roots": [cwd],
            "cwd": cwd,
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "call_1",
        })
    };
    // `toolArgs` arrives as a string of JSON rather than as the object Copilot's
    // reference documents.
    let copilot = |args: serde_json::Value| {
        serde_json::json!({
            "sessionId": "abc",
            "timestamp": "2026-09-07T10:00:00Z",
            "cwd": cwd,
            "toolName": "bash",
            "toolArgs": args.to_string(),
        })
    };
    let crush = |command: &str| {
        serde_json::json!({
            "event": "PreToolUse",
            "session_id": "abc",
            "cwd": cwd,
            "tool_name": "bash",
            "tool_input": { "command": command },
        })
    };
    let cline = |command: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "abc",
            "cwd": cwd,
            "tool": "execute_command",
            "parameters": { "command": command },
        })
    };
    let goose = |command: &str| {
        serde_json::json!({
            "event": "PreToolUse",
            "session_id": "abc",
            "tool_name": "developer__shell",
            "tool_input": { "command": command },
            "working_dir": cwd,
        })
    };
    // Windsurf sends neither a tool name nor a tool input object: the action it
    // fired on is the tool.
    let windsurf = |command: &str| {
        serde_json::json!({
            "agent_action_name": "pre_run_command",
            "trajectory_id": "traj_1",
            "execution_id": "exec_1",
            "timestamp": "2026-09-07T10:00:00Z",
            "model_name": "SWE-1",
            "tool_info": { "command_line": command, "cwd": cwd },
        })
    };
    let antigravity = |command: &str| {
        serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": command, "Cwd": cwd },
            },
            "stepIdx": 0,
            "conversationId": "abc",
            "workspacePaths": [cwd],
            "transcriptPath": "/home/u/.antigravity/session.json",
            "modelName": "gemini-3-pro",
        })
    };
    // The last three payloads are the ones steer's own shims send, not ones a
    // harness publishes: OpenCode, pi and Amp hand their plugin an in-process
    // object, and the shim forwards it as it stands.
    let opencode = |command: &str| {
        serde_json::json!({
            "tool": "bash",
            "args": { "command": command, "description": "clear the build" },
            "cwd": cwd,
        })
    };
    let pi = |command: &str| {
        serde_json::json!({
            "toolName": "bash",
            "input": { "command": command },
            "cwd": cwd,
        })
    };
    let amp = |command: &str| {
        serde_json::json!({
            "tool": "Bash",
            "input": { "cmd": command },
            "cwd": cwd,
        })
    };
    let envelope = |fields: serde_json::Value| serde_json::json!({ "hookSpecificOutput": fields });
    let held_back = "deletes stay recoverable\n\nRun this instead:\n\n  trash dist";

    // The last two columns are stderr and the exit code, which only Windsurf
    // uses: it publishes no decision document, so a deny is the code with the
    // reason beside it.
    let rows: &[(&str, serde_json::Value, serde_json::Value, &str, i32)] = &[
        (
            "claude",
            claude("Bash", serde_json::json!({ "command": "ls -la" })),
            serde_json::Value::Null,
            "",
            0,
        ),
        (
            "claude",
            claude(
                "Bash",
                serde_json::json!({ "command": "curl https://example.com" }),
            ),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "no network",
            })),
            "",
            0,
        ),
        // The rewrite edits the tool input rather than replacing it, so
        // everything the harness sent alongside the command survives.
        (
            "claude",
            claude(
                "Bash",
                serde_json::json!({ "command": "rm -rf dist", "description": "clear the build" }),
            ),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "updatedInput": { "command": "trash dist", "description": "clear the build" },
                "systemMessage": "deletes stay recoverable",
            })),
            "",
            0,
        ),
        (
            "claude",
            claude("Bash", serde_json::json!({ "command": "cargo test" })),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "additionalContext": "a note before the call",
            })),
            "",
            0,
        ),
        // Ingest, not matching, on both halves of the rule: it gates on `edit`
        // where the payload says `Edit`, and matches on `path` where the
        // payload says `file_path`.
        (
            "claude",
            claude(
                "Edit",
                serde_json::json!({
                    "file_path": format!("{cwd}/Cargo.lock"),
                    "old_string": "a",
                    "new_string": "b",
                }),
            ),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "regenerate the lockfile",
            })),
            "",
            0,
        ),
        // Codex reads the same envelope, so only the differing capability needs
        // rows of its own.
        (
            "codex",
            codex("curl https://example.com"),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "no network",
            })),
            "",
            0,
        ),
        (
            "codex",
            codex("rm -rf dist"),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": held_back,
            })),
            "",
            0,
        ),
        // Qwen reuses the envelope outright, so its rows are about ingest. It
        // publishes no file-tool input schema, so its descriptor renames no
        // file field and a payload spelling it `path` reaches the rules as it
        // stands — which is the case canonical `path` was chosen for.
        (
            "qwen",
            qwen(
                "run_shell_command",
                serde_json::json!({ "command": "rm -rf dist" }),
            ),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "updatedInput": { "command": "trash dist" },
                "systemMessage": "deletes stay recoverable",
            })),
            "",
            0,
        ),
        (
            "qwen",
            qwen(
                "replace",
                serde_json::json!({
                    "path": format!("{cwd}/Cargo.lock"),
                    "old_string": "a",
                    "new_string": "b",
                }),
            ),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "regenerate the lockfile",
            })),
            "",
            0,
        ),
        (
            "continue",
            continue_dev("rm -rf dist"),
            envelope(serde_json::json!({
                "hookEventName": "PreToolUse",
                "updatedInput": { "command": "trash dist" },
                "systemMessage": "deletes stay recoverable",
            })),
            "",
            0,
        ),
        (
            "junie",
            junie("curl https://example.com"),
            serde_json::json!({ "decision": "block", "reason": "no network" }),
            "",
            0,
        ),
        (
            "junie",
            junie("rm -rf dist"),
            serde_json::json!({
                "updatedInput": { "command": "trash dist" },
                "additionalContext": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        (
            "junie",
            junie("cargo test"),
            serde_json::json!({ "additionalContext": "a note before the call" }),
            "",
            0,
        ),
        (
            "gemini",
            gemini("curl https://example.com"),
            serde_json::json!({ "decision": "deny", "reason": "no network" }),
            "",
            0,
        ),
        (
            "gemini",
            gemini("rm -rf dist"),
            serde_json::json!({
                "hookSpecificOutput": { "tool_input": { "command": "trash dist" } },
                "systemMessage": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        // `BeforeTool` has nowhere to put a note, so the rule drops and the
        // call goes through unremarked.
        (
            "gemini",
            gemini("cargo test"),
            serde_json::Value::Null,
            "",
            0,
        ),
        // Cursor answers the model and the user in separate fields, and a deny
        // has to reach the model.
        (
            "cursor",
            cursor(
                "Shell",
                serde_json::json!({ "command": "curl https://example.com" }),
            ),
            serde_json::json!({ "permission": "deny", "agent_message": "no network" }),
            "",
            0,
        ),
        (
            "cursor",
            cursor("Shell", serde_json::json!({ "command": "rm -rf dist" })),
            serde_json::json!({
                "updated_input": { "command": "trash dist" },
                "user_message": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        // The `edit` rule fires on a `Write`, which is the only tool Cursor has
        // for either changing a file or making one.
        (
            "cursor",
            cursor(
                "Write",
                serde_json::json!({
                    "path": format!("{cwd}/Cargo.lock"),
                    "contents": "a",
                }),
            ),
            serde_json::json!({
                "permission": "deny",
                "agent_message": "regenerate the lockfile",
            }),
            "",
            0,
        ),
        (
            "copilot",
            copilot(serde_json::json!({ "command": "curl https://example.com" })),
            serde_json::json!({
                "permissionDecision": "deny",
                "permissionDecisionReason": "no network",
            }),
            "",
            0,
        ),
        (
            "copilot",
            copilot(
                serde_json::json!({ "command": "rm -rf dist", "description": "clear the build" }),
            ),
            serde_json::json!({
                "modifiedArgs": { "command": "trash dist", "description": "clear the build" },
                "permissionDecisionReason": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        (
            "crush",
            crush("curl https://example.com"),
            serde_json::json!({ "version": 1, "decision": "deny", "reason": "no network" }),
            "",
            0,
        ),
        (
            "crush",
            crush("rm -rf dist"),
            serde_json::json!({
                "version": 1,
                "updated_input": { "command": "trash dist" },
                "context": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        (
            "crush",
            crush("cargo test"),
            serde_json::json!({ "version": 1, "context": "a note before the call" }),
            "",
            0,
        ),
        // Cline denies by cancelling, and takes no edited input at all, so the
        // rewrite arrives as a deny naming the command to run instead.
        (
            "cline",
            cline("curl https://example.com"),
            serde_json::json!({ "cancel": true, "errorMessage": "no network" }),
            "",
            0,
        ),
        (
            "cline",
            cline("rm -rf dist"),
            serde_json::json!({ "cancel": true, "errorMessage": held_back }),
            "",
            0,
        ),
        (
            "cline",
            cline("cargo test"),
            serde_json::json!({
                "cancel": false,
                "contextModification": "a note before the call",
            }),
            "",
            0,
        ),
        // Goose reads Junie's shape, so its rows are about ingest —
        // `developer__shell` and `working_dir` — and about what it cannot do.
        (
            "goose",
            goose("curl https://example.com"),
            serde_json::json!({ "decision": "block", "reason": "no network" }),
            "",
            0,
        ),
        (
            "goose",
            goose("rm -rf dist"),
            serde_json::json!({ "decision": "block", "reason": held_back }),
            "",
            0,
        ),
        ("goose", goose("cargo test"), serde_json::Value::Null, "", 0),
        (
            "windsurf",
            windsurf("curl https://example.com"),
            serde_json::Value::Null,
            "no network",
            2,
        ),
        (
            "windsurf",
            windsurf("rm -rf dist"),
            serde_json::Value::Null,
            held_back,
            2,
        ),
        (
            "windsurf",
            windsurf("ls -la"),
            serde_json::Value::Null,
            "",
            0,
        ),
        (
            "antigravity",
            antigravity("curl https://example.com"),
            serde_json::json!({ "decision": "deny", "reason": "no network" }),
            "",
            0,
        ),
        (
            "antigravity",
            antigravity("rm -rf dist"),
            serde_json::json!({ "decision": "deny", "reason": held_back }),
            "",
            0,
        ),
        // The three shim harnesses share one shape, so their rows differ only
        // in where the shim found the tool name and the command.
        (
            "opencode",
            opencode("curl https://example.com"),
            serde_json::json!({ "outcome": "deny", "message": "no network" }),
            "",
            0,
        ),
        // A rewrite hands back the command alone: the shim assigns it into the
        // arguments object the harness is holding, so nothing beside it — the
        // description here — has to survive a round trip.
        (
            "opencode",
            opencode("rm -rf dist"),
            serde_json::json!({
                "outcome": "rewrite",
                "updated_command": "trash dist",
                "message": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        // An allow says so rather than saying nothing, because the shim reads
        // silence as steer having fallen over.
        (
            "opencode",
            opencode("ls -la"),
            serde_json::json!({ "outcome": "allow" }),
            "",
            0,
        ),
        // The `context` rule drops before it is evaluated, so a note steer
        // cannot deliver never becomes an outcome the shim cannot use.
        (
            "opencode",
            opencode("cargo test"),
            serde_json::json!({ "outcome": "allow" }),
            "",
            0,
        ),
        // The file field is renamed the same way the command is: OpenCode says
        // `filePath` where the rule says `path`.
        (
            "opencode",
            serde_json::json!({
                "tool": "edit",
                "args": {
                    "filePath": format!("{cwd}/Cargo.lock"),
                    "oldString": "a",
                    "newString": "b",
                },
                "cwd": cwd,
            }),
            serde_json::json!({ "outcome": "deny", "message": "regenerate the lockfile" }),
            "",
            0,
        ),
        (
            "pi",
            pi("curl https://example.com"),
            serde_json::json!({ "outcome": "deny", "message": "no network" }),
            "",
            0,
        ),
        (
            "pi",
            pi("rm -rf dist"),
            serde_json::json!({
                "outcome": "rewrite",
                "updated_command": "trash dist",
                "message": "deletes stay recoverable",
            }),
            "",
            0,
        ),
        (
            "amp",
            amp("curl https://example.com"),
            serde_json::json!({ "outcome": "deny", "message": "no network" }),
            "",
            0,
        ),
        (
            "amp",
            amp("rm -rf dist"),
            serde_json::json!({
                "outcome": "rewrite",
                "updated_command": "trash dist",
                "message": "deletes stay recoverable",
            }),
            "",
            0,
        ),
    ];

    for (harness, payload, expected, errors, exit) in rows {
        let (stdout, stderr, code) = sandbox.output(
            &["hook", "--event", "PreToolUse", "--agent", harness],
            &payload.to_string(),
        );
        assert_eq!(code, *exit, "{harness}: {stderr}");
        let response = match stdout.trim().is_empty() {
            true => serde_json::Value::Null,
            false => serde_json::from_str(&stdout).expect("hook output is json"),
        };
        assert_eq!(&response, expected, "{harness} on {payload}");
        assert_eq!(stderr.trim(), *errors, "{harness} on {payload}");
    }
}

// `ruby` is deliberately untouched by any built-in, so only this rule is in
// play.
const PER_AGENT: &str = r#"
[[rules]]
name = "ruby-per-agent"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
claude = "Use the Edit tool."
codex = "Use apply_patch."
"#;

// The matching is harness-independent; only the tool it points at is not. A
// single message forces a rule to either name one harness's tools or be gated
// off the other entirely, which throws the matching away with it.
#[test]
fn a_message_can_name_a_different_tool_per_harness() {
    let sandbox = Sandbox::new("peragent");
    sandbox.write_global(PER_AGENT);
    let payload = bash_payload("ruby script.rb", Some(&sandbox.work()));

    let claude = sandbox.hook_as("claude", "PreToolUse", &payload);
    assert!(is_denied(&claude), "{claude}");
    assert!(reason(&claude).contains("Edit tool"), "{claude}");

    let codex = sandbox.hook_as("codex", "PreToolUse", &payload);
    assert!(is_denied(&codex), "{codex}");
    assert!(reason(&codex).contains("apply_patch"), "{codex}");
}

// Naming a harness in the table is the gate: a rule with nothing to say to a
// harness has nothing followable to deny it with either.
#[test]
fn a_harness_the_message_does_not_name_is_not_covered() {
    let sandbox = Sandbox::new("peragentgate");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-claude-only"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
claude = "Use the Edit tool."
"#,
    );
    let payload = bash_payload("ruby script.rb", Some(&sandbox.work()));

    assert!(is_denied(&sandbox.hook_as(
        "claude",
        "PreToolUse",
        &payload
    )));
    assert_eq!(
        sandbox.hook_as("codex", "PreToolUse", &payload),
        serde_json::Value::Null,
        "expected a clean allow"
    );
}

// Naming a harness is the gate only while the table names harnesses. `default`
// is how a rule opts out of it, and without that opt-out a rule silently stops
// applying to whichever harness ships next.
#[test]
fn a_default_message_covers_a_harness_the_table_does_not_name() {
    let sandbox = Sandbox::new("defaultmessage");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-default"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
default = "Use a real edit tool."
codex = "Use `apply_patch`."
"#,
    );
    let payload = bash_payload("ruby script.rb", Some(&sandbox.work()));

    let claude = sandbox.hook_as("claude", "PreToolUse", &payload);
    assert!(is_denied(&claude), "{claude}");
    assert_eq!(reason(&claude), "Use a real edit tool.");

    let codex = sandbox.hook_as("codex", "PreToolUse", &payload);
    assert!(is_denied(&codex), "{codex}");
    assert_eq!(reason(&codex), "Use `apply_patch`.");
}

// A deny has to name a tool the model can call, and no name is common to every
// harness, so a `default` writes a token and the harness in front of it fills
// the token in. Codex has no search tool to fill `{search}` with, so `requires`
// takes the rule away from it rather than leaving the token standing.
#[test]
fn a_tool_token_renders_as_the_harnesss_own_name() {
    let sandbox = Sandbox::new("vocabulary");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-tokens"
tool = "shell"
requires = ["search", "edit"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
default = "Search with {search} and edit with {edit}."
"#,
    );
    let payload = bash_payload("ruby script.rb", Some(&sandbox.work()));

    let claude = sandbox.hook_as("claude", "PreToolUse", &payload);
    assert_eq!(reason(&claude), "Search with Grep and edit with Edit.");

    let qwen_payload = serde_json::json!({
        "cwd": sandbox.work().display().to_string(),
        "tool_name": "run_shell_command",
        "tool_input": { "command": "ruby script.rb" },
    })
    .to_string();
    let qwen = sandbox.hook_as("qwen", "PreToolUse", &qwen_payload);
    assert_eq!(
        reason(&qwen),
        "Search with search_file_content and edit with replace."
    );

    assert_eq!(
        sandbox.hook_as("codex", "PreToolUse", &payload),
        serde_json::Value::Null,
        "Codex has no search tool, so the rule does not reach it"
    );
}

// The per-harness verdict is where a rule that stopped reaching a harness
// becomes visible, so the reason a capability gate gives is part of the report
// rather than an internal string.
#[test]
fn the_verdict_names_the_tool_a_harness_does_not_have() {
    let sandbox = Sandbox::new("verdict");
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("codex, goose: dropped, no read tool"), "{out}");
}

// The hole this gate closes: without it a rule writing `{read}` renders "use
// shell to read a file" on the two harnesses whose read is the shell, which is
// a deny recommending the command it just refused.
#[test]
fn a_token_for_a_tool_the_rule_does_not_require_is_a_problem() {
    let sandbox = Sandbox::new("unrequiredtoken");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-unrequired"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"
message = "Use {read} instead."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("ruby-unrequired"), "{out}");
    assert!(out.contains("requires = [\"read\"]"), "{out}");
}

// `agents` and `requires` are independent, and a rule that satisfies neither
// anywhere is one nobody can see the effect of.
#[test]
fn gates_that_together_reach_no_harness_are_a_problem() {
    let sandbox = Sandbox::new("emptygate");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-nowhere"
tool = "shell"
agents = ["codex"]
requires = ["read"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"
message = "Use a read tool."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("ruby-nowhere"), "{out}");
    assert!(out.contains("reach no harness"), "{out}");
}

// A name outside the vocabulary is a typo, and reporting it as a rule that
// reaches nothing would send the reader looking at the gates instead.
#[test]
fn a_requires_naming_something_that_is_not_a_tool_says_so() {
    let sandbox = Sandbox::new("badrequires");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-typo"
tool = "shell"
requires = ["reed"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"
message = "Use a read tool."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("reed"), "{out}");
    assert!(out.contains("shell, read, edit, write, search"), "{out}");
}

// A `default` covers every harness, so the table beside an `agents` gate is the
// copy the gated harnesses read rather than a second gate that could disagree.
#[test]
fn an_agents_gate_may_carry_a_default_message() {
    let sandbox = Sandbox::new("gateplusdefault");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-claude-with-default"
tool = "shell"
agents = ["claude"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
default = "Use a real edit tool."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");

    let payload = bash_payload("ruby script.rb", Some(&sandbox.work()));
    assert!(is_denied(&sandbox.hook_as(
        "claude",
        "PreToolUse",
        &payload
    )));
    assert_eq!(
        sandbox.hook_as("codex", "PreToolUse", &payload),
        serde_json::Value::Null,
        "the `agents` gate still holds"
    );
}

// Two gates on one rule that can disagree is a rule nobody can read.
#[test]
fn a_per_harness_message_beside_an_agents_gate_is_a_problem() {
    let sandbox = Sandbox::new("peragentboth");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-double-gate"
tool = "shell"
agents = ["claude"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
claude = "Use the Edit tool."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("ruby-double-gate"), "{out}");
    assert!(out.contains("agents"), "{out}");
}

// A key in the table is the gate, so a typo silently narrows the rule to the
// harnesses that are left — and the untagged shape reported it as the whole
// action failing to match anything.
#[test]
fn a_mistyped_harness_key_names_itself_and_the_keys_it_could_be() {
    let sandbox = Sandbox::new("peragenttypo");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-typo"
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
claudde = "Use the Edit tool."
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("claudde"), "{out}");
    assert!(out.contains("default|claude|codex"), "{out}");
}

// The PATH gate and the nested-span hold-back both run before the agent split,
// so a rewrite that cannot be spliced still allows everywhere.
#[test]
fn a_held_back_rewrite_allows_on_every_agent() {
    let sandbox = Sandbox::new("heldboth");
    sandbox.stub_binary("trash");

    let payload = bash_payload("bash -lc 'rm -rf dist'", Some(&sandbox.work()));
    for agent in ["claude", "codex"] {
        assert_eq!(
            sandbox.hook_as(agent, "PreToolUse", &payload),
            serde_json::Value::Null,
            "{agent}"
        );
    }
}

#[test]
fn a_rule_gated_on_an_agent_is_invisible_to_the_others() {
    let sandbox = Sandbox::new("agentgate");
    sandbox.stub_binary("trash");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-apply-patch"
tool = "shell"
agents = ["codex"]

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["apply_patch"] }

[rules.action]
kind = "deny"
message = "edit the file directly"
"#,
    );

    let gated = bash_payload("apply_patch spec.md", Some(&sandbox.work()));
    assert!(!is_denied(&sandbox.hook_as("claude", "PreToolUse", &gated)));
    assert!(is_denied(&sandbox.hook_as("codex", "PreToolUse", &gated)));

    // `trash-over-rm` names no agent, so both harnesses act on it.
    let rm = bash_payload("rm -rf dist", Some(&sandbox.work()));
    assert!(sandbox
        .hook_as("claude", "PreToolUse", &rm)
        .pointer("/hookSpecificOutput/updatedInput")
        .is_some());
    assert!(is_denied(&sandbox.hook_as("codex", "PreToolUse", &rm)));
}

// Harnesses copy each other's payload shapes, so inferring one from the shape
// would run a harness's guidance under another. Defaulting is worse than asking:
// that failure lands in the model's context rather than on a terminal.
#[test]
fn a_payload_naming_no_agent_allows_and_names_the_flag() {
    let sandbox = Sandbox::new("noagent");
    sandbox.stub_binary("trash");
    let value = sandbox.decide(
        &["hook", "--event", "PreToolUse"],
        &bash_payload("rm -rf dist", Some(&sandbox.work())),
    );
    assert!(!is_denied(&value));
    assert!(value.pointer("/hookSpecificOutput/updatedInput").is_none());

    let message = note(&value);
    assert!(message.contains("--agent"), "{message}");
}

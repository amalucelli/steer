// The built-in rules, driven through the real binary the way Claude Code drives
// it: a hook payload on stdin, `hookSpecificOutput` on stdout.
//
// The fff-over-grep table is carried over verbatim from the shell hook that
// preceded steer, which was tuned against live sessions. It is the acceptance
// bar for the port, not a starting point.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_steer");

// Removes the sandbox on drop so a panicking test still cleans up.
struct Sandbox {
    dir: PathBuf,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Sandbox {
    /// A working tree with no config of its own, plus an XDG config home that
    /// is empty, so only the built-in rules are in play.
    fn new(name: &str) -> Sandbox {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("steer-test-{name}-{}-{n}", std::process::id()));
        fs::create_dir_all(dir.join("work")).expect("create sandbox");
        fs::create_dir_all(dir.join("config")).expect("create config home");
        fs::create_dir_all(dir.join("state")).expect("create state home");
        fs::create_dir_all(dir.join("bin")).expect("create bin");
        Sandbox { dir }
    }

    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    fn write(&self, rel: &str, contents: &str) {
        let path = self.work().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    fn write_global(&self, contents: &str) {
        let path = self.dir.join("config").join("steer").join("config.toml");
        fs::create_dir_all(path.parent().unwrap()).expect("create config dir");
        fs::write(path, contents).expect("write global config");
    }

    /// Puts an executable stub of `name` on the PATH the binary will see.
    fn stub_binary(&self, name: &str) {
        let path = self.dir.join("bin").join(name);
        fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        }
    }

    fn log_lines(&self) -> Vec<String> {
        let path = self.dir.join("state").join("steer").join("steer.jsonl");
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.current_dir(self.work())
            .args(args)
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env("PATH", self.dir.join("bin"));
        cmd
    }

    fn hook(&self, event: &str, payload: &str) -> serde_json::Value {
        let stdout = self.run(&["hook", "--event", event], payload);
        if stdout.trim().is_empty() {
            return serde_json::Value::Null;
        }
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad hook output {stdout:?}: {e}"))
    }

    fn run(&self, args: &[&str], stdin: &str) -> String {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn steer");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        let out = child.wait_with_output().expect("wait steer");
        assert_eq!(
            out.status.code(),
            Some(0),
            "the hook path must always exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn bash_payload(command: &str) -> String {
    serde_json::json!({
        "session_id": "test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

fn decision(sandbox: &Sandbox, command: &str) -> serde_json::Value {
    sandbox.hook("PreToolUse", &bash_payload(command))
}

fn is_denied(value: &serde_json::Value) -> bool {
    value
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(serde_json::Value::as_str)
        == Some("deny")
}

fn denied_by(sandbox: &Sandbox, rule: &str) -> Vec<String> {
    sandbox
        .log_lines()
        .into_iter()
        .filter(|line| line.contains(rule))
        .collect()
}

// The table the shell hook was validated against, run end to end.
#[test]
fn fff_over_grep_seed_cases() {
    let sandbox = Sandbox::new("seed");

    let deny: &[&str] = &[
        r#"bash -c 'grep -rn -i "virtual" src/Chat.tsx | head -20'"#,
        r#"grep -rn "func .*Conv" --include="*.go" pkg/domains 2>/dev/null | head"#,
        r#"rg -n "createVirtualizer" src"#,
        r#"find . -name "*.tsx" -path "*chat*""#,
        "git grep -n Conversation",
        "cd /repo && grep -rn foo src/",
        "GOFLAGS=-mod=mod grep -rn foo src/",
    ];
    let allow: &[&str] = &[
        "gh pr list | grep foo",
        "go test ./... | grep FAIL",
        r#"rg -n "solid-virtual" node_modules/@tanstack"#,
        "grep -rn foo /usr/local/include",
    ];

    for command in deny {
        assert!(
            is_denied(&decision(&sandbox, command)),
            "expected deny: {command}"
        );
    }
    for command in allow {
        let value = decision(&sandbox, command);
        assert!(!is_denied(&value), "expected allow: {command} got {value}");
    }
}

// `sed -n` is a file read, so fff-over-grep must not claim it; read-over-sed
// owns the redirect and names itself in the log.
#[test]
fn sed_belongs_to_read_over_sed() {
    let sandbox = Sandbox::new("sed");
    let command = "sed -n 800,900p pkg/chats/sharing.go";
    assert!(is_denied(&decision(&sandbox, command)));
    assert!(denied_by(&sandbox, "fff-over-grep").is_empty());
    assert_eq!(denied_by(&sandbox, "read-over-sed").len(), 1);
}

// `git -C <path>` is the form the model is told to use for other-repo work, so
// it has to reach the same rule a bare `git grep` does.
#[test]
fn git_global_options_do_not_hide_a_search() {
    let sandbox = Sandbox::new("gitopts");
    for command in [
        "git grep -n Conversation",
        "git -C /repo grep -n Conversation",
        "git --no-pager -c core.pager=cat grep -n Conversation",
    ] {
        assert!(is_denied(&decision(&sandbox, command)), "{command}");
    }
    // The subcommand still has to be `grep`; git's options must not shift it.
    assert!(!is_denied(&decision(
        &sandbox,
        "git -C /repo commit -m grep"
    )));
}

// A find that acts on what it traverses is not a search, and the fff tools
// cannot delete or exec — denying it would leave nowhere to go.
#[test]
fn find_with_an_action_primary_is_not_a_search() {
    let sandbox = Sandbox::new("findaction");
    for command in [
        r#"find . -name "*.pyc" -delete"#,
        "find . -type f -exec chmod 644 {} +",
        "find . -name '*.tmp' -execdir rm {} ;",
    ] {
        assert!(!is_denied(&decision(&sandbox, command)), "{command}");
    }
    // Still a search without one, per the seed table.
    assert!(is_denied(&decision(
        &sandbox,
        r#"find . -name "*.tsx" -path "*chat*""#
    )));
}

// The fff tools are deferred in this build, so a blocked model that has not
// loaded their schemas cannot call what the message names.
#[test]
fn the_deny_message_names_the_schema_loader() {
    let sandbox = Sandbox::new("toolsearch");
    let reason = decision(&sandbox, "grep -rn foo src")
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(serde_json::Value::as_str)
        .expect("a deny reason")
        .to_string();
    assert!(reason.contains("ToolSearch"), "{reason}");
    assert!(reason.contains("select:mcp__fff__grep"), "{reason}");
}

// The regression the table exists to pin: a prefix matcher loose enough to
// treat `--include="*.go"` as a variable assignment consumed the flag and let
// the search through.
#[test]
fn include_flag_is_not_an_assignment() {
    let sandbox = Sandbox::new("include");
    assert!(is_denied(&decision(
        &sandbox,
        r#"grep -rn foo --include="*.go" pkg"#
    )));
}

// The escape the port is meant to close: with `if` left unpeeled the segment
// head was `if`, and no search rule ever saw the grep.
#[test]
fn shell_keywords_do_not_hide_a_search() {
    let sandbox = Sandbox::new("keywords");
    for command in [
        "if grep -q foo file; then echo yes; fi",
        "for f in *.go; do grep -n x $f; done",
        "while grep -q foo file; do sleep 1; done",
    ] {
        assert!(is_denied(&decision(&sandbox, command)), "{command}");
    }
}

#[test]
fn sed_after_a_pipe_is_a_filter() {
    let sandbox = Sandbox::new("sedpipe");
    assert!(!is_denied(&decision(&sandbox, "cat foo | sed -n '1,5p'")));
}

#[test]
fn rewrite_replaces_the_head_and_drops_recursive_flags() {
    let sandbox = Sandbox::new("rewrite");
    sandbox.stub_binary("trash");

    let value = decision(&sandbox, "cd build && rm -rf dist");
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!("cd build && trash dist"))
    );
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
tool = "Bash"

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

// Rules address a non-Bash payload through the same paths, without a `parsed`
// object in play.
#[test]
fn a_rule_matches_a_non_bash_tool() {
    let sandbox = Sandbox::new("nonbash");
    sandbox.write_global(
        r#"
[[rules]]
name = "no-lockfile-edits"
tool = "Edit"

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
    assert!(is_denied(&sandbox.hook("PreToolUse", &payload)));
}

#[test]
fn post_tool_use_only_injects_context() {
    let sandbox = Sandbox::new("post");
    sandbox.write_global(
        r#"
[[rules]]
name = "note-tests"
tool = "Bash"

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
    assert_eq!(entry["tool_input"]["command"], "grep -rn foo src");
}

#[test]
fn an_allowed_call_is_not_logged() {
    let sandbox = Sandbox::new("nolog");
    decision(&sandbox, "gh pr list | grep foo");
    assert!(sandbox.log_lines().is_empty());
}

// Fail-open is the hard requirement: nothing steer does may block a call it did
// not mean to block.
#[test]
fn broken_input_and_broken_config_still_allow() {
    let sandbox = Sandbox::new("failopen");

    for stdin in ["", "not json at all", "{\"tool_name\": 5}"] {
        let stdout = sandbox.run(&["hook", "--event", "PreToolUse"], stdin);
        assert!(!stdout.contains("\"deny\""), "denied on {stdin:?}");
    }

    sandbox.write_global("this is not = valid toml [[[\n");
    let stdout = sandbox.run(
        &["hook", "--event", "PreToolUse"],
        &bash_payload("grep -rn foo src"),
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(!is_denied(&value));
    let message = value
        .pointer("/hookSpecificOutput/systemMessage")
        .and_then(serde_json::Value::as_str)
        .expect("systemMessage names the breakage");
    assert!(message.contains("steer"), "{message}");
}

#[test]
fn an_unknown_event_allows_rather_than_blocks() {
    let sandbox = Sandbox::new("badevent");
    let stdout = sandbox.run(
        &["hook", "--event", "Nonsense"],
        &bash_payload("grep -rn x src"),
    );
    assert!(stdout.contains("systemMessage"), "{stdout}");
    assert!(!stdout.contains("\"deny\""));
}

fn cli(sandbox: &Sandbox, args: &[&str]) -> (String, i32) {
    let out = sandbox.command(args).output().expect("run steer");
    (
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn check_prints_the_parse_the_rule_and_the_message() {
    let sandbox = Sandbox::new("check");
    let (out, code) = cli(&sandbox, &["check", "grep -rn foo src"]);
    assert_eq!(code, 1, "a denied command reports a nonzero status");
    assert!(out.contains("head=grep"), "{out}");
    assert!(out.contains("pipeline_start=true"), "{out}");
    assert!(out.contains("fff-over-grep"), "{out}");
    assert!(out.contains("mcp__fff__grep"), "{out}");

    let (out, code) = cli(&sandbox, &["check", "gh pr list | grep foo"]);
    assert_eq!(code, 0);
    assert!(out.contains("action   allow"), "{out}");
}

#[test]
fn check_reports_a_rewrite_held_back_by_a_missing_binary() {
    let sandbox = Sandbox::new("checkheld");
    let (out, _) = cli(&sandbox, &["check", "rm -rf dist"]);
    assert!(out.contains("trash-over-rm"), "{out}");
    assert!(out.contains("not on PATH"), "{out}");
}

#[test]
fn validate_accepts_the_built_ins_alone() {
    let sandbox = Sandbox::new("validok");
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("ok"), "{out}");
}

#[test]
fn validate_reports_the_file_and_line_of_each_problem() {
    let sandbox = Sandbox::new("validbad");
    sandbox.write_global(
        r#"disable = ["no-such-rule"]

[[rules]]
name = "dup"
[[rules.match]]
file_path = { glob = ["["] }
[rules.action]
kind = "deny"
message = "x"

[[rules]]
name = "dup"
[[rules.match]]
file_path = { any_of = ["y"] }
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

#[test]
fn validate_rejects_an_unknown_field() {
    let sandbox = Sandbox::new("validunknown");
    sandbox.write_global(
        r#"
[[rules]]
name = "typo"
tolo = "Bash"
[[rules.match]]
file_path = { any_of = ["y"] }
[rules.action]
kind = "deny"
message = "x"
"#,
    );
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("tolo"), "{out}");
}

#[test]
fn init_writes_a_starter_config_once() {
    let sandbox = Sandbox::new("init");
    let (_, code) = cli(&sandbox, &["init"]);
    assert_eq!(code, 0);
    let path = sandbox.dir.join("config").join("steer").join("config.toml");
    assert!(Path::new(&path).is_file());

    let (out, code) = cli(&sandbox, &["init"]);
    assert_eq!(code, 2, "a second init must not clobber the first");
    assert!(out.contains("already exists"), "{out}");
}

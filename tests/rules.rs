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

fn bash_payload(command: &str, cwd: Option<&Path>) -> String {
    let mut payload = serde_json::json!({
        "session_id": "test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    if let Some(cwd) = cwd {
        payload["cwd"] = serde_json::json!(cwd.display().to_string());
    }
    payload.to_string()
}

fn decision(sandbox: &Sandbox, command: &str) -> serde_json::Value {
    let payload = bash_payload(command, Some(&sandbox.work()));
    sandbox.hook("PreToolUse", &payload)
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
        r#"bash -c 'grep -rn -i "render" src/Widget.tsx | head -20'"#,
        r#"grep -rn "func .*Handler" --include="*.go" pkg/thing 2>/dev/null | head"#,
        r#"rg -n "createWidget" src"#,
        r#"find . -name "*.tsx" -path "*panel*""#,
        "git grep -n RecordStore",
        "cd /repo && grep -rn foo src/",
        "GOFLAGS=-mod=mod grep -rn foo src/",
    ];
    let allow: &[&str] = &[
        "gh pr list | grep foo",
        "go test ./... | grep FAIL",
        r#"rg -n "some-lib" node_modules/@scope"#,
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

// `sed -n` is a file read, so fff-over-grep must not claim it; the pager rule
// owns the redirect and names itself in the log.
#[test]
fn sed_belongs_to_the_pager_rule() {
    let sandbox = Sandbox::new("sed");
    let command = "sed -n 800,900p pkg/thing/widget.go";
    assert!(is_denied(&decision(&sandbox, command)));
    assert!(denied_by(&sandbox, "fff-over-grep").is_empty());
    assert_eq!(denied_by(&sandbox, "read-over-shell-pager").len(), 1);
}

// Blocking one spelling of "give me a line range from this file" only moves the
// intent to the next, so the rule covers the family. Observed in a live
// session: denied `sed -n`, the model reached for `cat -n`, then a piped
// `head`, then `awk 'NR>=x && NR<=y'`.
#[test]
fn every_spelling_of_a_windowed_read_is_denied() {
    let sandbox = Sandbox::new("pager");

    let deny: &[&str] = &[
        "cat -n app/ts/clients/component.api.ts",
        "awk 'NR>=655 && NR<=710' pkg/go/thing/widget.go",
        "cat apps/web/src/dataFetch.ts | head -120",
        "sed -n 800,900p pkg/thing/widget.go",
        // Reading a file into any filter is still reading a file: the leading
        // `cat` is what the rule claims, whatever comes after the pipe.
        "cat data.json | sed -n 1,5p",
        "cat data.json | grep foo",
    ];
    let allow: &[&str] = &[
        // awk computing over a file rather than paging one.
        "awk '{sum+=$1} END{print sum}' data.csv",
        // A filter on output that already exists: the producer is a command,
        // not a file read.
        "git log | awk '{print $1}'",
        "git log | sed -n 1,5p",
        // No file operand: a heredoc write and a bare pager.
        "cat > clean.sh <<EOF\nx\nEOF\n",
        "head -5",
        // Following a log is not a windowed read, and neither is a file
        // outside the workspace.
        "tail -f logs/app.log",
        "cat /etc/hosts",
    ];

    for command in deny {
        assert!(is_denied(&decision(&sandbox, command)), "{command:?}");
    }
    for command in allow {
        assert!(!is_denied(&decision(&sandbox, command)), "{command:?}");
    }
}

// Claude Code writes absolute paths constantly, so testing the spelling of a
// path rather than where it lands let most real searches through: the same
// search of the same tree was denied relative and allowed absolute.
#[test]
fn an_absolute_path_into_the_workspace_is_still_a_workspace_search() {
    let sandbox = Sandbox::new("abspath");
    let w = sandbox.work().display().to_string();

    let deny: &[String] = &[
        format!("grep -rn X {w}/pkg/go/thing/"),
        "grep -rn X pkg/go/thing/".to_string(),
        "grep -rn X".to_string(),
        "cd sub && grep -rn X .".to_string(),
    ];
    let allow: &[String] = &[
        "grep -rn X /usr/local/include".to_string(),
        "grep -rn X /home/u/work/other-project/src".to_string(),
        format!("grep -rn X {w}/node_modules/pkg"),
        "grep -rn X ~/Desktop/notes".to_string(),
    ];

    for command in deny {
        assert!(is_denied(&decision(&sandbox, command)), "{command}");
    }
    for command in allow {
        assert!(!is_denied(&decision(&sandbox, command)), "{command}");
    }
}

// Where the workspace is comes from the payload alone. Without it the rule
// declines rather than guessing, which is the fail-open default everywhere.
#[test]
fn a_payload_without_cwd_allows() {
    let sandbox = Sandbox::new("nocwd");
    let payload = bash_payload("grep -rn X pkg/go/thing/", None);
    assert!(!is_denied(&sandbox.hook("PreToolUse", &payload)));
}

// `git -C <path>` is the form the model is told to use for other-repo work, so
// it has to reach the same rule a bare `git grep` does.
#[test]
fn git_global_options_do_not_hide_a_search() {
    let sandbox = Sandbox::new("gitopts");
    for command in [
        "git grep -n RecordStore",
        "git -C /repo grep -n RecordStore",
        "git --no-pager -c core.pager=cat grep -n RecordStore",
    ] {
        assert!(is_denied(&decision(&sandbox, command)), "{command}");
    }
    // The subcommand still has to be `grep`; git's options must not shift it.
    assert!(!is_denied(&decision(
        &sandbox,
        "git -C /repo commit -m grep"
    )));
}

// A whole program written inline to stdin is file surgery; `-c` is a short
// computation. Matching one and not the other is the whole precision of this
// rule, so both halves are pinned here.
#[test]
fn inline_python_programs_are_denied_and_computations_are_not() {
    let sandbox = Sandbox::new("python");

    let deny: &[&str] = &[
        "python3 - <<'PY'\nimport pathlib\npathlib.Path('x').write_text('y')\nPY\n",
        "python - <<EOF\nprint(1)\nEOF\n",
    ];
    let allow: &[&str] = &[
        // A filter being fed data, not a program editing files. The producer is
        // a command rather than `cat <file>`, which read-over-shell-pager would
        // claim on its own account.
        "git log | python3 -",
        "python3 -c 'print(1/3)'",
        "python3 -c 'import json; json.load(f)'",
        "python3 script.py",
        "python3 -m pytest",
    ];

    for command in deny {
        assert!(is_denied(&decision(&sandbox, command)), "{command:?}");
    }
    for command in allow {
        assert!(!is_denied(&decision(&sandbox, command)), "{command:?}");
    }
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
        r#"find . -name "*.tsx" -path "*panel*""#
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

// The producer here is a command, so nothing in the pipeline is a file read and
// the `sed` block's `pipeline_start` gate is the only thing under test.
#[test]
fn sed_after_a_pipe_is_a_filter() {
    let sandbox = Sandbox::new("sedpipe");
    assert!(!is_denied(&decision(&sandbox, "git log | sed -n '1,5p'")));
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
        &bash_payload("grep -rn foo src", Some(&sandbox.work())),
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
        &bash_payload("grep -rn x src", Some(&sandbox.work())),
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

// A heredoc body is data — a script being written, a SQL blob, a commit
// message. Lexing it as commands let a rewrite splice into the contents of a
// file rather than into a command, changing what the user wrote with nothing in
// the transcript to show it.
#[test]
fn a_heredoc_body_is_never_matched_or_rewritten() {
    let sandbox = Sandbox::new("heredoc");
    sandbox.stub_binary("trash");

    for command in [
        "cat > clean.sh <<'EOF'\nrm -rf build\nEOF\n",
        "cat <<-EOF\n\trm -rf build\n\tEOF\n",
    ] {
        let value = decision(&sandbox, command);
        assert_eq!(value, serde_json::Value::Null, "{command:?}");
    }

    // A search written into a file is text, not a search.
    let value = decision(&sandbox, "cat > x.sh <<EOF\ngrep -rn foo src/\nEOF\n");
    assert!(!is_denied(&value), "{value}");

    // The skip stops at the terminator, so a command after it is still seen and
    // is the only thing the rewrite touches.
    let value = decision(&sandbox, "cat <<EOF\nx\nEOF\nrm -rf build");
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!("cat <<EOF\nx\nEOF\ntrash build"))
    );
}

// edit-over-python fires on the invocation, which is outside the body it now
// skips.
#[test]
fn skipping_bodies_does_not_disarm_the_python_rule() {
    let sandbox = Sandbox::new("heredocpython");
    assert!(is_denied(&decision(
        &sandbox,
        "python3 - <<'PY'\nprint(1)\nPY\n"
    )));
}

// A herestring is a single word, not a body. `heredoc_at` declines on `<<<`,
// so it takes the path it always did and the line after it is still a command
// rather than something to skip.
#[test]
fn a_herestring_is_unaffected() {
    let sandbox = Sandbox::new("herestring");
    sandbox.stub_binary("trash");

    // The herestring's own segment reads as it always did: its target word is
    // consumed as a redirect target, leaving `grep foo` a search.
    assert!(is_denied(&decision(&sandbox, "grep foo <<< \"$var\"")));

    let value = decision(&sandbox, "cat <<< \"$var\"\nrm -rf build");
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!("cat <<< \"$var\"\ntrash build")),
        "the line after a herestring is still a command"
    );
}

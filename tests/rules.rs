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

    fn global_text(&self) -> String {
        let path = self.dir.join("config").join("steer").join("config.toml");
        fs::read_to_string(path).unwrap_or_default()
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

    /// Writes the log the reading commands read, for the pairs that are
    /// tedious to produce by driving the hook.
    /// One log line as the hook writes it, from the sandbox's own workspace so
    /// `in_workspace` weighs the same way it did when the call ran.
    fn entry(
        &self,
        ts_ms: u64,
        outcome: &str,
        rules: serde_json::Value,
        command: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "ts_ms": ts_ms,
            "outcome": outcome,
            "rules": rules,
            "tool_name": "Bash",
            "session_id": "s1",
            "cwd": self.work().display().to_string(),
            "tool_input": { "command": command },
        })
    }

    fn write_log(&self, entries: &[serde_json::Value]) {
        let dir = self.dir.join("state").join("steer");
        fs::create_dir_all(&dir).expect("create state dir");
        let lines: Vec<String> = entries.iter().map(|entry| entry.to_string()).collect();
        fs::write(dir.join("steer.jsonl"), lines.join("\n") + "\n").expect("write log");
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
        self.decide(&["hook", "--event", event, "--agent", "claude"], payload)
    }

    fn hook_as(&self, agent: &str, event: &str, payload: &str) -> serde_json::Value {
        self.decide(&["hook", "--event", event, "--agent", agent], payload)
    }

    fn decide(&self, args: &[&str], payload: &str) -> serde_json::Value {
        let stdout = self.run(args, payload);
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

fn transcript_payload(command: &str, cwd: &Path, transcript: &str) -> String {
    let mut payload: serde_json::Value =
        serde_json::from_str(&bash_payload(command, Some(cwd))).expect("payload json");
    payload["transcript_path"] = serde_json::json!(transcript);
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
        // Read reaches outside the tree, so where the file sits is not a way
        // out. Parking a diff in /tmp and paging it there was the live escape.
        "cat /tmp/review.diff",
        "cat /etc/hosts",
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
        // Following a log is not a windowed read.
        "tail -f logs/app.log",
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
        // Bare `python3` fed by a heredoc reads its program from stdin with no
        // argument at all, so there is no `args.0` to match on.
        "python3 <<'PY'\nopen(p, 'w').write(s)\nPY\n",
        "python <<'EOF'\nprint(1)\nEOF\n",
        // A REPL an agent has no use for, blocked as a side effect and accepted.
        "python3",
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

// The same intent as the inline program, spelled as a flag. Observed in a live
// session: denied a `grep` of src/main.rs, the model came back a minute later
// with `sed -i '' '/.../d' src/main.rs` and edited the file with nothing in the
// transcript to review.
#[test]
fn in_place_stream_edits_are_denied_and_stream_transforms_are_not() {
    let sandbox = Sandbox::new("inplace");

    let deny: &[&str] = &[
        "sed -i '' '/about = env!(\"CARGO_PKG_DESCRIPTION\"),/d' src/main.rs",
        "sed -i.bak 's/a/b/' src/main.rs",
        "perl -0pi -e 's{a}{b}' Taskfile.yml",
        "perl -Ilib -pi -e 's/a/b/' src/main.rs",
        "gsed --in-place 's/a/b/' src/main.rs",
        "awk -i inplace '{print}' src/main.rs",
        // Uppercase inside the bundle is what `-MList::Util` is held out by, so
        // the one real spelling that carries it has to still land.
        "sed -Ei '' 's/a/b/' src/main.rs",
        // No workspace guard: an unreviewable edit is one wherever it lands.
        "sed -i '' 's/a/b/' /tmp/scratch.txt",
    ];
    let allow: &[&str] = &[
        // The false positives the run's alphabet exists to exclude. The last is
        // a program written tight against its flag, which reaches the rule as
        // `-eprint 1` once the quotes are stripped.
        "perl -MList::Util -e 1",
        "perl -mstrict -e 1",
        "perl -Ilib -pe 'print' f",
        "perl -lane 'print $F[0]' f",
        "perl -e'print 1'",
        // Writing to stdout or into a pipe transforms a stream, and edits
        // nothing.
        "sed -E 's/a/b/' in.txt > out.txt",
        "git diff | perl -pe 's/a/b/'",
        "awk '{print $1}' data.csv",
    ];

    for command in deny {
        assert!(is_denied(&decision(&sandbox, command)), "{command:?}");
    }
    for command in allow {
        assert!(!is_denied(&decision(&sandbox, command)), "{command:?}");
    }
}

// The second built-in to reach both harnesses, so the tool its guidance names
// has to follow the harness rather than the rule.
#[test]
fn the_in_place_deny_names_each_harnesss_edit_tool() {
    let sandbox = Sandbox::new("inplaceagents");
    let payload = bash_payload("sed -i '' 's/a/b/' src/main.rs", Some(&sandbox.work()));

    let claude = sandbox.hook_as("claude", "PreToolUse", &payload);
    assert!(is_denied(&claude), "{claude}");
    assert!(reason(&claude).contains("Edit tool"), "{claude}");

    let codex = sandbox.hook_as("codex", "PreToolUse", &payload);
    assert!(is_denied(&codex), "{codex}");
    assert!(reason(&codex).contains("apply_patch"), "{codex}");
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

// Codex accepts `updatedInput` only alongside an approval, which would put the
// rewritten command past the permission prompt, so the new command has to reach
// the model as guidance instead.
#[test]
fn a_rewrite_becomes_a_deny_carrying_the_command_on_codex() {
    let sandbox = Sandbox::new("codexrewrite");
    sandbox.stub_binary("trash");

    let payload = bash_payload("cd build && rm -rf dist", Some(&sandbox.work()));
    let value = sandbox.hook_as("codex", "PreToolUse", &payload);
    assert!(is_denied(&value), "{value}");
    assert!(value.pointer("/hookSpecificOutput/updatedInput").is_none());

    let reason = value
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(serde_json::Value::as_str)
        .expect("a deny reason");
    assert!(reason.contains("cd build && trash dist"), "{reason}");
}

// A rewrite that only injects a flag, which is what the `--no-ext-diff` case
// needs: no head to replace, so nothing for the PATH gate to look up either.
const ADD_ARGS: &str = r#"
[[rules]]
name = "git-diff-no-ext-diff"
tool = "Bash"

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
    decision(sandbox, command)
        .pointer("/hookSpecificOutput/updatedInput/command")
        .and_then(serde_json::Value::as_str)
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
// idempotence of its own — and a rewrite with no head must not be held back by
// a PATH gate that has nothing to look up.
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

// One rule, one message per harness it speaks to. `ruby` is deliberately
// untouched by any built-in, so only this rule is in play.
const PER_AGENT: &str = r#"
[[rules]]
name = "ruby-per-agent"
tool = "Bash"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["ruby"] }

[rules.action]
kind = "deny"

[rules.action.message]
claude = "Use the Edit tool."
codex = "Use apply_patch."
"#;

fn reason(value: &serde_json::Value) -> String {
    value
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

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
tool = "Bash"

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

// Two gates on one rule that can disagree is a rule nobody can read.
#[test]
fn a_per_harness_message_beside_an_agents_gate_is_a_problem() {
    let sandbox = Sandbox::new("peragentboth");
    sandbox.write_global(
        r#"
[[rules]]
name = "ruby-double-gate"
tool = "Bash"
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
tool = "Bash"
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

// Claude Code keeps transcripts under `~/.claude/projects/` and Codex under
// `~/.codex/sessions/`, which is enough to tell them apart with no flag in the
// registration at all.
#[test]
fn the_transcript_path_picks_the_harness() {
    let sandbox = Sandbox::new("detect");
    sandbox.stub_binary("trash");

    let codex = sandbox.decide(
        &["hook", "--event", "PreToolUse"],
        &transcript_payload(
            "rm -rf dist",
            &sandbox.work(),
            "/home/u/.codex/sessions/2026/09/01/rollout.jsonl",
        ),
    );
    assert!(is_denied(&codex), "{codex}");

    let claude = sandbox.decide(
        &["hook", "--event", "PreToolUse"],
        &transcript_payload(
            "rm -rf dist",
            &sandbox.work(),
            "/home/u/.claude/projects/-repo/session.jsonl",
        ),
    );
    assert_eq!(
        claude.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!("trash dist"))
    );
}

// The flag is the escape hatch for a setup detection does not fit, so it has to
// win outright rather than only break a tie.
#[test]
fn an_explicit_agent_beats_the_transcript_path() {
    let sandbox = Sandbox::new("override");
    sandbox.stub_binary("trash");
    let payload = transcript_payload(
        "rm -rf dist",
        &sandbox.work(),
        "/home/u/.claude/projects/-repo/session.jsonl",
    );
    assert!(is_denied(&sandbox.hook_as("codex", "PreToolUse", &payload)));
}

// Defaulting to one harness would run its guidance under the other, and that
// failure lands in the model's context rather than on a terminal.
#[test]
fn an_unidentifiable_harness_allows_and_names_the_flag() {
    let sandbox = Sandbox::new("noagent");
    sandbox.stub_binary("trash");
    let value = sandbox.decide(
        &["hook", "--event", "PreToolUse"],
        &bash_payload("rm -rf dist", Some(&sandbox.work())),
    );
    assert!(!is_denied(&value));
    assert!(value.pointer("/hookSpecificOutput/updatedInput").is_none());

    let message = value
        .pointer("/hookSpecificOutput/systemMessage")
        .and_then(serde_json::Value::as_str)
        .expect("systemMessage names the breakage");
    assert!(message.contains("--agent"), "{message}");
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
    assert_eq!(entry["harness"], "claude");
    assert_eq!(entry["tool_input"]["command"], "grep -rn foo src");
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
        &["hook", "--event", "PreToolUse", "--agent", "claude"],
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

fn cli(sandbox: &Sandbox, args: &[&str]) -> (String, i32) {
    let out = sandbox.command(args).output().expect("run steer");
    (
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        out.status.code().unwrap_or(-1),
    )
}

// "Nothing matched" is an answer without a reason. The reason is one condition
// on one segment, and it is the whole point of running check on a command that
// surprised you.
#[test]
fn check_names_the_condition_that_held_a_rule_back() {
    let sandbox = Sandbox::new("nearest");
    let (out, code) = cli(&sandbox, &["check", "gh pr list | grep foo"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("nearest   fff-over-grep"), "{out}");
    assert!(out.contains("✗ pipeline_start"), "{out}");
    assert!(out.contains("actual=false"), "{out}");

    // A rule wanting a different binary is not a near miss, whatever else of it
    // happens to hold.
    assert!(!out.contains("edit-over-python"), "{out}");

    let (out, _) = cli(&sandbox, &["check", "grep -rn foo src"]);
    assert!(
        out.contains("matched   fff-over-grep  (block 0, parsed.segments[0])"),
        "{out}"
    );
}

// A transition between two outcome names is the engine's vocabulary, not a
// consequence. The report has to say what would happen to the call, that
// nothing was written, and — since a log outlives the rules that answered it —
// whether any of it is recent enough to be about a rule you just wrote.
#[test]
fn replay_reports_the_consequence_and_the_age_of_a_difference() {
    let sandbox = Sandbox::new("replaydrift");
    sandbox.write_log(&[serde_json::json!({
        "ts_ms": 1_000,
        "outcome": "deny",
        "rules": ["fff-over-grep"],
        "tool_name": "Bash",
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

    // The window takes units, since checking a rule just written is a question
    // about the last few minutes.
    let (out, code) = cli(&sandbox, &["replay", "--since", "30m"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("none would land differently"), "{out}");

    let (out, code) = cli(&sandbox, &["replay", "--since", "5x"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("unknown unit `x`"), "{out}");
}

// A draft is a recommendation whatever the comments around it say, so the one
// case where the tool is unsure has to produce no draft at all — and say why
// where a reader is looking, which is not inside a file they have not pasted.
#[test]
fn draft_declines_when_the_rule_does_not_know_the_command_that_followed() {
    let sandbox = Sandbox::new("weak");
    let entry = |ts_ms: u64, outcome: &str, rules: serde_json::Value, command: &str| {
        serde_json::json!({
            "ts_ms": ts_ms,
            "outcome": outcome,
            "rules": rules,
            "tool_name": "Bash",
            "session_id": "s1",
            "tool_input": { "command": command },
        })
    };
    sandbox.write_log(&[
        entry(
            1_000,
            "deny",
            serde_json::json!(["fff-over-grep"]),
            "grep -n ts:security Taskfile.yml",
        ),
        entry(9_000, "allow", serde_json::json!([]), "task ts:security"),
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

    // Asking for them says the same thing in a line, per pair.
    let (out, _) = cli(&sandbox, &["suggest", "--all"]);
    assert!(
        out.contains("signal  the rule says nothing about `task`"),
        "{out}"
    );
}

// A log outlives the rules read against it, so the same pair keeps coming back
// long after the edit that closed it. Sorting is what makes the report
// actionable: the pair today's rules answer is finished, and the one still
// getting through is named with the condition an edit would go to.
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

    // And it pastes: the narrowed block closes the escape without touching what
    // the rule declares it must leave alone.
    let (draft, _) = cli(&sandbox, &["suggest", "--draft", "fff-over-grep"]);
    sandbox.write_global(&draft);
    let (out, code) = cli(&sandbox, &["validate"]);
    assert_eq!(code, 0, "the narrowed draft holds its own examples: {out}");
    sandbox.write_global("");

    // The other answer, and the one a log can take on its own. It writes to the
    // config `suggest` was run in, records every fix as an escape its rule
    // allows, and the finding is answered.
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

// A draft is a paste, so the only test that means anything is the paste: write
// it where a config goes and ask the binary to read it back. The escape here is
// a heredoc, which is the shape that put a document into the comment block and
// left every line of it after the first as bare TOML.
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
    // And the two halves interlocking. `cat > out <<EOF` is an escape the pager
    // rule declares, and here even the narrowed block reaches it — dropping the
    // `matches` that held the escape open is what the escape *was*. `validate`
    // names the contradiction, which is the report saying closing was the wrong
    // answer for this one.
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

// The built-ins are opinions, and they are not everyone's. Naming all of them
// in `disable` is complete only until the next one ships, so starting from none
// of them is its own setting — and the report has to show what it turned off
// rather than an empty stack.
#[test]
fn builtins_can_be_switched_off_wholesale() {
    let sandbox = Sandbox::new("nobuiltins");
    sandbox.write_global(
        r#"
builtins = false

[[rules]]
name = "mine"
tool = "Bash"
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

    // The rules are gone from the decision, not merely from the report.
    assert!(!is_denied(&decision(&sandbox, "grep -rn foo src")), "{out}");
    assert!(is_denied(&decision(&sandbox, "psql -h prod")), "{out}");
}

// An example that stops being true has to fail, or it is just a comment.
#[test]
fn validate_runs_the_examples_a_rule_declares() {
    let sandbox = Sandbox::new("examples");
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
tool = "Bash"
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

// A command the rule does not touch has no output to claim.
#[test]
fn a_rewrites_example_on_a_rule_that_never_rewrites_is_a_problem() {
    let sandbox = Sandbox::new("rewritewrongkind");
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
fn help_lists_every_subcommand() {
    let sandbox = Sandbox::new("help");
    let (out, code) = cli(&sandbox, &["--help"]);
    assert_eq!(code, 0, "{out}");
    for subcommand in ["hook", "check", "validate", "init"] {
        assert!(out.contains(subcommand), "{subcommand} missing from {out}");
    }
    assert!(out.contains("Examples:"), "{out}");
}

#[test]
fn a_misspelled_flag_is_corrected_rather_than_dumped() {
    let sandbox = Sandbox::new("typo");
    let (out, code) = cli(&sandbox, &["--verson"]);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("a similar argument exists: '--version'"),
        "{out}"
    );
}

#[test]
fn the_version_flag_keeps_its_short_form() {
    let sandbox = Sandbox::new("version");
    let (out, code) = cli(&sandbox, &["-v"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.starts_with(&format!("steer {}", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );
}

// clap reports help through the same `Err` as a parse failure, so the fail-open
// branch has to let it past instead of wrapping it in a decision envelope.
#[test]
fn hook_help_prints_help_not_a_decision() {
    let sandbox = Sandbox::new("hookhelp");
    let (out, code) = cli(&sandbox, &["hook", "--help"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("--event"), "{out}");
    assert!(!out.contains("hookSpecificOutput"), "{out}");
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
    assert!(out.contains("action    allow"), "{out}");
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
tool = "Bash"
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
    assert!(out.contains("ok        4 rules"), "{out}");
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

// The guarantee is not about one line ending: appending any character to a
// terminator must not reduce what steer can see. Swallowing to end of input on
// a near-miss made every following command invisible to every rule, so one
// stray byte disabled enforcement for the rest of the call.
#[test]
fn a_terminator_near_miss_never_hides_what_follows() {
    let sandbox = Sandbox::new("heredocblind");
    sandbox.stub_binary("trash");

    let sed = "sed -n '1,5p' f.txt";
    for terminator in ["PY\n", "PY\r\n", "PY \n", "PY\t\n", "PY;\n"] {
        let command = format!("cat <<'PY'\nx\n{terminator}{sed}");
        assert!(
            is_denied(&decision(&sandbox, &command)),
            "terminator {terminator:?} hid the command after it"
        );
    }

    // A closed body is still data, and the rewrite after it still lands on the
    // command rather than on the contents.
    let value = decision(&sandbox, "cat <<'PY'\nrm -rf inside\nPY\nrm -rf build");
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!(
            "cat <<'PY'\nrm -rf inside\nPY\ntrash build"
        )),
        "the body must survive byte for byte"
    );

    // An unterminated heredoc leaves the remainder visible rather than blind,
    // and must not panic.
    decision(&sandbox, "cat <<'PY'\nrm -rf build\n");
    decision(&sandbox, "cat <<'PY'");
}

// Bash runs an unterminated heredoc rather than rejecting it: it warns, treats
// EOF as the delimiter, and writes the body. So a rewrite aimed at body text
// steer misread as a command would land in the file the heredoc feeds — the
// same silent corruption the body skip was added to prevent, arriving through
// the recovery path. Deny and context still fire; they change no bytes.
#[test]
fn an_unclosed_heredoc_suppresses_rewrites_but_not_denies() {
    let sandbox = Sandbox::new("recovered");
    sandbox.stub_binary("trash");

    // Closed: the rewrite lands on the trailing command, body untouched.
    let value = decision(
        &sandbox,
        "cat > out.sh <<'PY'\nrm -rf build\nPY\nrm -rf dist",
    );
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!(
            "cat > out.sh <<'PY'\nrm -rf build\nPY\ntrash dist"
        ))
    );

    // Unclosed: the body's `rm` is not a command, so nothing may be rewritten.
    let value = decision(&sandbox, "cat > out.sh <<'PY'\nrm -rf build\n");
    assert!(
        value.pointer("/hookSpecificOutput/updatedInput").is_none(),
        "rewrote a misread heredoc body: {value}"
    );

    // A deny on recovered text is still correct — it blocks and mutates
    // nothing, which is why lexing the remainder is worth doing at all.
    assert!(is_denied(&decision(
        &sandbox,
        "cat <<'PY'\nx\nPY \nsed -n '1,5p' f.txt"
    )));

    // A carriage return still closes the heredoc, so this parse is clean and
    // the rewrite applies as normal.
    let value = decision(&sandbox, "cat <<'PY'\nx\nPY\r\nrm -rf build");
    assert_eq!(
        value.pointer("/hookSpecificOutput/updatedInput/command"),
        Some(&serde_json::json!("cat <<'PY'\nx\nPY\r\ntrash build"))
    );
}

// `steer check` names the hold-back, so a suppressed rewrite is explainable
// rather than looking like the rule simply failed to match.
#[test]
fn check_reports_a_rewrite_held_back_by_a_dirty_parse() {
    let sandbox = Sandbox::new("checkrecovered");
    sandbox.stub_binary("trash");
    let (out, _) = cli(&sandbox, &["check", "cat <<'PY'\nrm -rf build\n"]);
    assert!(out.contains("trash-over-rm"), "{out}");
    assert!(out.contains("did not parse cleanly"), "{out}");
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

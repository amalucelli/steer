// The temp-dir harness every test drives the binary through: a working tree
// with an XDG config and state home of its own.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_steer");

pub struct Sandbox {
    pub dir: PathBuf,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Sandbox {
    /// Starts with no config anywhere, so only the built-in rules are in play.
    pub fn new(name: &str) -> Sandbox {
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

    pub fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    pub fn write(&self, rel: &str, contents: &str) {
        let path = self.work().join(rel);
        fs::create_dir_all(path.parent().unwrap()).expect("create parent");
        fs::write(path, contents).expect("write file");
    }

    pub fn write_global(&self, contents: &str) {
        let path = self.dir.join("config").join("steer").join("config.toml");
        fs::create_dir_all(path.parent().unwrap()).expect("create config dir");
        fs::write(path, contents).expect("write global config");
    }

    pub fn global_text(&self) -> String {
        let path = self.dir.join("config").join("steer").join("config.toml");
        fs::read_to_string(path).unwrap_or_default()
    }

    pub fn stub_binary(&self, name: &str) {
        let path = self.dir.join("bin").join(name);
        fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        }
    }

    pub fn log_lines(&self) -> Vec<String> {
        let path = self.dir.join("state").join("steer").join("steer.jsonl");
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// One log line as the hook writes it, from the sandbox's own workspace so
    /// `in_workspace` weighs the same way it did when the call ran.
    pub fn entry(
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
            "tool_name": "shell",
            "session_id": "s1",
            "cwd": self.work().display().to_string(),
            "tool_input": { "command": command },
        })
    }

    pub fn write_log(&self, entries: &[serde_json::Value]) {
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

    pub fn hook(&self, event: &str, payload: &str) -> serde_json::Value {
        self.decide(&["hook", "--event", event, "--agent", "claude"], payload)
    }

    pub fn hook_as(&self, agent: &str, event: &str, payload: &str) -> serde_json::Value {
        self.decide(&["hook", "--event", event, "--agent", agent], payload)
    }

    pub fn decide(&self, args: &[&str], payload: &str) -> serde_json::Value {
        let stdout = self.run(args, payload);
        if stdout.trim().is_empty() {
            return serde_json::Value::Null;
        }
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad hook output {stdout:?}: {e}"))
    }

    pub fn run(&self, args: &[&str], stdin: &str) -> String {
        let (stdout, stderr, code) = self.output(args, stdin);
        assert_eq!(
            code, 0,
            "the hook path must always exit 0; stderr: {stderr}"
        );
        stdout
    }

    /// Keeps the exit code: some harnesses read it as the decision itself.
    pub fn output(&self, args: &[&str], stdin: &str) -> (String, String, i32) {
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
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }
}

pub fn bash_payload(command: &str, cwd: Option<&Path>) -> String {
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

pub fn decision(sandbox: &Sandbox, command: &str) -> serde_json::Value {
    let payload = bash_payload(command, Some(&sandbox.work()));
    sandbox.hook("PreToolUse", &payload)
}

pub fn is_denied(value: &serde_json::Value) -> bool {
    value
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(serde_json::Value::as_str)
        == Some("deny")
}

pub fn denied_by(sandbox: &Sandbox, rule: &str) -> Vec<String> {
    sandbox
        .log_lines()
        .into_iter()
        .filter(|line| line.contains(rule))
        .collect()
}

pub fn reason(value: &serde_json::Value) -> String {
    value
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn updated_command(value: &serde_json::Value) -> Option<&str> {
    value
        .pointer("/hookSpecificOutput/updatedInput/command")
        .and_then(serde_json::Value::as_str)
}

pub fn note(value: &serde_json::Value) -> &str {
    value
        .pointer("/hookSpecificOutput/systemMessage")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

pub fn cli(sandbox: &Sandbox, args: &[&str]) -> (String, i32) {
    let out = sandbox.command(args).output().expect("run steer");
    (
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        out.status.code().unwrap_or(-1),
    )
}

use crate::sandbox::{cli, Sandbox};

// "Nothing matched" is an answer without a reason. The reason is one condition
// on one segment.
#[test]
fn check_prints_the_parse_the_rule_and_the_near_miss() {
    let sandbox = Sandbox::new("check");

    let (out, code) = cli(&sandbox, &["check", "grep -rn foo src"]);
    assert_eq!(code, 1, "a denied command reports a nonzero status");
    assert!(out.contains("head=grep"), "{out}");
    assert!(out.contains("pipeline_start=true"), "{out}");
    assert!(out.contains("mcp__fff__grep"), "{out}");
    assert!(
        out.contains("matched   fff-over-grep  (block 0, parsed.segments[0])"),
        "{out}"
    );

    let (out, code) = cli(&sandbox, &["check", "gh pr list | grep foo"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("action    allow"), "{out}");
    assert!(out.contains("nearest   fff-over-grep"), "{out}");
    assert!(out.contains("✗ pipeline_start"), "{out}");
    assert!(out.contains("actual=false"), "{out}");

    // A rule wanting a different binary is not a near miss, whatever else of it
    // happens to hold.
    assert!(!out.contains("edit-over-python"), "{out}");
}

// `check` speaks for no harness, so it has no vocabulary to render a tool token
// through.
#[test]
fn check_shows_a_per_harness_message_as_the_rule_wrote_it() {
    let sandbox = Sandbox::new("checkmessage");
    let (out, code) = cli(&sandbox, &["check", "sed -i '' 's/a/b/' src/main.rs"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("default: Use the {edit} tool"), "{out}");
    assert!(out.contains("codex: Use `apply_patch`"), "{out}");
}

#[test]
fn help_lists_every_subcommand() {
    let sandbox = Sandbox::new("help");
    let (out, code) = cli(&sandbox, &["--help"]);
    assert_eq!(code, 0, "{out}");
    for subcommand in ["hook", "check", "replay", "suggest", "validate", "init"] {
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
fn check_reports_a_rewrite_held_back_by_a_missing_binary() {
    let sandbox = Sandbox::new("checkheld");
    let (out, _) = cli(&sandbox, &["check", "rm -rf dist"]);
    assert!(out.contains("trash-over-rm"), "{out}");
    assert!(out.contains("not on PATH"), "{out}");
}

#[test]
fn init_writes_a_starter_config_once() {
    let sandbox = Sandbox::new("init");
    let (_, code) = cli(&sandbox, &["init"]);
    assert_eq!(code, 0);
    let path = sandbox.dir.join("config").join("steer").join("config.toml");
    assert!(path.is_file());

    let (out, code) = cli(&sandbox, &["init"]);
    assert_eq!(code, 2, "a second init must not clobber the first");
    assert!(out.contains("already exists"), "{out}");
    assert!(out.contains("--force"), "{out}");
}

// Refusing is right for a file someone may have edited, but a generated shim
// stops matching the binary it spawns the moment steer is upgraded, and
// replacing it should not mean deleting it first.
#[test]
fn init_force_replaces_what_is_already_there() {
    let sandbox = Sandbox::new("initforce");
    let (out, code) = cli(&sandbox, &["init", "--agent", "opencode"]);
    assert_eq!(code, 0, "{out}");

    let path = sandbox.work().join(".opencode/plugins/steer.js");
    std::fs::write(&path, "// an older steer wrote this\n").expect("stale shim");
    let (out, code) = cli(&sandbox, &["init", "--agent", "opencode", "--force"]);
    assert_eq!(code, 0, "{out}");

    let source = std::fs::read_to_string(&path).expect("read shim");
    assert!(!source.contains("an older steer"), "{source}");
}

// The shim is the whole registration for these three, so where it lands and
// what it is called are the contract rather than a detail.
#[test]
fn init_writes_a_shim_where_its_harness_looks_for_one() {
    let sandbox = Sandbox::new("initshim");
    // The JS shims spawn through an argv array and pi through a shell string,
    // so the harness name is pinned as each file actually spells it.
    for (agent, rel, spawn) in [
        (
            "opencode",
            ".opencode/plugins/steer.js",
            r#""--agent", "opencode""#,
        ),
        ("pi", ".pi/extensions/steer.ts", "--agent pi"),
        ("amp", ".amp/plugins/steer.js", r#""--agent", "amp""#),
    ] {
        let (out, code) = cli(&sandbox, &["init", "--agent", agent]);
        assert_eq!(code, 0, "{out}");
        let path = sandbox.work().join(rel);
        assert!(path.is_file(), "{agent} wrote nothing to {rel}");
        assert!(out.contains(rel), "{out}");

        // A shim copied from one harness and edited into another is caught here.
        let source = std::fs::read_to_string(&path).expect("read shim");
        assert!(source.contains(spawn), "{agent}: {source}");
    }
}

// A harness steer is registered into by config has nothing to write, and a
// plugin file dropped in its project would sit there doing nothing.
#[test]
fn init_declines_a_harness_that_needs_no_shim() {
    let sandbox = Sandbox::new("initnoshim");
    let (out, code) = cli(&sandbox, &["init", "--agent", "claude"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("opencode"), "{out}");
    assert!(!sandbox.work().join(".claude").exists(), "{out}");
}

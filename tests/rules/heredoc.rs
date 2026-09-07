// Heredoc lexing, where a mistake is silent: a body is data, so nothing in it
// may match and nothing may be spliced into it.

use crate::sandbox::{cli, decision, is_denied, updated_command, Sandbox};

// Lexing a heredoc body as commands let a rewrite splice into the contents of a
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

    let value = decision(&sandbox, "cat > x.sh <<EOF\ngrep -rn foo src/\nEOF\n");
    assert!(!is_denied(&value), "{value}");

    // The skip stops at the terminator, so a command after it is still seen.
    let value = decision(&sandbox, "cat <<EOF\nx\nEOF\nrm -rf build");
    assert_eq!(
        updated_command(&value),
        Some("cat <<EOF\nx\nEOF\ntrash build")
    );
}

// Swallowing to end of input on a near-miss made every following command
// invisible to every rule, so one stray byte disabled enforcement for the rest
// of the call.
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

    let value = decision(&sandbox, "cat <<'PY'\nrm -rf inside\nPY\nrm -rf build");
    assert_eq!(
        updated_command(&value),
        Some("cat <<'PY'\nrm -rf inside\nPY\ntrash build"),
        "the body must survive byte for byte"
    );

    // An unterminated heredoc must not panic.
    decision(&sandbox, "cat <<'PY'\nrm -rf build\n");
    decision(&sandbox, "cat <<'PY'");
}

// Bash runs an unterminated heredoc rather than rejecting it: it warns, treats
// EOF as the delimiter, and writes the body. So a rewrite aimed at body text
// steer misread as a command would land in the file the heredoc feeds. Deny and
// context still fire; they change no bytes.
#[test]
fn an_unclosed_heredoc_suppresses_rewrites_but_not_denies() {
    let sandbox = Sandbox::new("recovered");
    sandbox.stub_binary("trash");

    let value = decision(
        &sandbox,
        "cat > out.sh <<'PY'\nrm -rf build\nPY\nrm -rf dist",
    );
    assert_eq!(
        updated_command(&value),
        Some("cat > out.sh <<'PY'\nrm -rf build\nPY\ntrash dist")
    );

    let value = decision(&sandbox, "cat > out.sh <<'PY'\nrm -rf build\n");
    assert!(
        value.pointer("/hookSpecificOutput/updatedInput").is_none(),
        "rewrote a misread heredoc body: {value}"
    );

    assert!(is_denied(&decision(
        &sandbox,
        "cat <<'PY'\nx\nPY \nsed -n '1,5p' f.txt"
    )));

    // A carriage return still closes the heredoc, so this parse is clean.
    let value = decision(&sandbox, "cat <<'PY'\nx\nPY\r\nrm -rf build");
    assert_eq!(
        updated_command(&value),
        Some("cat <<'PY'\nx\nPY\r\ntrash build")
    );
}

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

// A herestring is a single word, not a body.
#[test]
fn a_herestring_is_unaffected() {
    let sandbox = Sandbox::new("herestring");
    sandbox.stub_binary("trash");

    // The herestring's target word is consumed as a redirect target, leaving
    // `grep foo` a search.
    assert!(is_denied(&decision(&sandbox, "grep foo <<< \"$var\"")));

    let value = decision(&sandbox, "cat <<< \"$var\"\nrm -rf build");
    assert_eq!(
        updated_command(&value),
        Some("cat <<< \"$var\"\ntrash build"),
        "the line after a herestring is still a command"
    );
}

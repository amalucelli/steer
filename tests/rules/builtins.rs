// The seed cases for the built-in rules, most of them a spelling a live
// session produced.
//
// The fff-over-grep table is carried over verbatim from the shell hook that
// preceded steer, which was tuned against live sessions. It is the acceptance
// bar for the port, not a starting point.

use crate::sandbox::{bash_payload, decision, denied_by, is_denied, reason, Sandbox};

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
// computation.
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
    // Still a search without one.
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
    let value = decision(&sandbox, "grep -rn foo src");
    assert!(reason(&value).contains("ToolSearch"), "{value}");
    assert!(reason(&value).contains("select:mcp__fff__grep"), "{value}");
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

# steer

A rule engine that sits in front of an agent's tool calls. It sees each call before it runs and
either **denies** it with guidance the model reads, **rewrites** its input in place, or lets it
through with **context** attached. Rules live in TOML, so redirecting a new tool is a config entry
rather than another branch in a growing shell script.

It exists because a harness can outrank you. Claude Code's auto mode injects a system directive to
search with shell `grep` and read with `sed -n`; it beats anything in `CLAUDE.md`, and no setting
turns it off. A hook is the last layer that still gets to decide.

```
$ steer check 'cd build && rm -rf dist'
command  cd build && rm -rf dist
segments
  head=cd args=["build"] pipeline_start=true depth=0
  head=rm args=["-rf", "dist"] pipeline_start=true depth=0
matched  trash-over-rm
action   rewrite
rewrite  cd build && trash dist
```

## Install

```sh
cargo install --path . --root ~/.local
```

Then register it in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "steer hook --event PreToolUse" }] }
    ]
  }
}
```

No config file is needed. The built-in rules are compiled into the binary and active on install.

Register `PostToolUse` the same way once you have a `context` rule for it. None of the built-ins
are, so adding it before then spends a process launch on every tool result and changes nothing.

## Config

Rules come from three places, each stacking on the one before:

1. **Built-ins**, compiled into the binary and active with no config file at all.
2. **`~/.config/steer/config.toml`** — your base, the one to keep in dotfiles. Honors
   `$XDG_CONFIG_HOME`. `steer init` writes a commented starter here.
3. **`.steer.toml` in the repo**, found by walking up from the session's working directory —
   whatever this one project needs.

A later source replaces an earlier rule of the same name, and `disable` switches one off wherever
it came from:

```toml
# .steer.toml — no fff index in this repo, but psql reaches a live database
disable = ["fff-over-grep"]

[[rules]]
name = "no-prod-psql"
tool = "Bash"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["psql"] }

[rules.action]
kind = "deny"
message = "Use the read replica: psql -h replica.internal."
```

What a repo file cannot do is quietly soften a rule it does not name. Every matching rule is
evaluated and the strongest action wins, so putting a `context` rule beside an inherited `deny`
still denies. Switching one off takes `disable`, by name, in the open.

`steer validate` reports unknown fields, bad globs and regexes, duplicate rule names, and a
`disable` naming a rule nothing defines — with file and line.

## Commands

```
steer hook --event PreToolUse|PostToolUse   read a hook payload on stdin, decide on stdout
steer check '<command>'                     dry-run a Bash command through the rules
steer validate                              report problems in every config source
steer init                                  write a starter global config
```

`steer check` exits 1 when the command would be denied, so it drops into a script.

`PostToolUse` accepts only `context` rules in v0.1. Denying or rewriting a call that already ran
means nothing, and what else belongs there needs its own design pass.

## Writing a rule

A tool call arrives as JSON: a tool name and that tool's input. steer copies it into a match
document, adds `parsed.segments` when the tool is Bash, evaluates every rule against it, and
returns the strongest action any of them asked for — **deny > rewrite > context**. Reasons from
every matching rule are concatenated, so file order never changes the outcome.

A complete rule, ready to copy:

```toml
[[rules]]
name = "no-curl"
description = "Network fetches go through the WebFetch tool."
tool = "Bash"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["curl", "wget"] }
pipeline_start = { is = true }
args = { none_glob = ["http://localhost*", "http://127.0.0.1*"] }

[rules.action]
kind = "deny"
message = "Use WebFetch — it renders the page and stays in the transcript."
```

`tool` gates on the exact tool name; leave it out and the rule sees every tool.

**A rule fires when any of its `[[rules.match]]` blocks holds.** Blocks are alternatives — the
shape a rule is looking for, written more than one way. The built-in `fff-over-grep` uses two: one
for `grep`-like commands, one for `git grep`.

**A block holds when every condition in it holds against one binding.** This is what makes
correlation work. The block above asks whether *one* segment has head `curl` *and* starts its
pipeline *and* is not pointed at localhost. Without a shared binding, `gh pr list | curl -X POST`
would match by taking the head from the second segment and the pipeline position from the first.

### The match document

Every payload carries `tool_name` plus the tool's own input fields — `command` for Bash,
`file_path` for Read and Edit. A Bash payload also gets `parsed.segments`, one entry per pipeline
stage with its wrappers peeled:

| Field | |
| --- | --- |
| `head` | basename of the command, so `/usr/bin/grep` and `grep` compare equal |
| `args` | its arguments, unquoted, with redirection targets removed |
| `pipeline_start` | true when the stage runs first in its pipeline |
| `in_workspace` | true when the stage reaches into the session's working tree |
| `depth` | 0 for the command line, higher inside `bash -c` or `$(...)` |
| `wrappers` | what was peeled to get here |

`;`, `&&`, `||` and newlines start a new segment; `|` only advances the stage within one. A `grep`
after a pipe is filtering something that already ran, and `pipeline_start` is how a rule tells that
from a search.

Peeled as wrappers: leading `VAR=value` assignments — only when the name is a shell identifier, so
`--include="*.go"` survives — plus `env`, `sudo`, `time`, `nice`, `command`, `xargs`,
`timeout <duration>`, and the shell keywords `if`, `then`, `elif`, `else`, `while`, `until`, `do`.
`bash -c '...'` and `$(...)` re-enter the lexer on their script. `git` keeps its head but loses its
own leading options (`-C <path>`, `-c <k=v>`, `--git-dir`, …), so `args.0` is always the
subcommand. Heredoc bodies are data and produce no segments at all.

`in_workspace` is about where an argument lands, not how it is spelled — an absolute path into the
working tree is the same search as the relative one, and agents write absolute paths constantly.
Path-shaped arguments are resolved against the working directory (`~` expanded, `.` and `..`
folded, no disk access), and the segment counts as inside when any of them lands there, or when it
names no path at all. An argument carrying glob or regex metacharacters is what the command is
looking for rather than where. The field is absent when the payload carries no working directory,
so a rule asking for it declines rather than guessing.

### Paths

A condition key is a dotted path into the match document. Numeric parts index arrays: `"args.0"` is
the first argument, which is how `git grep` is told apart from `git commit`.

A block binds to the whole document unless it names an array:

| Key | Binding |
| --- | --- |
| *(neither)* | the document root |
| `any = "<path>"` | holds when some element of the array satisfies every condition |
| `all = "<path>"` | holds when every element does; an empty array never satisfies it |

### Operators

| Operator | Holds when |
| --- | --- |
| `any_of = [...]` | the value equals one of these |
| `none_of = [...]` | it equals none of them |
| `glob = [...]` | it matches one of these glob patterns |
| `none_glob = [...]` | it matches none of them |
| `matches = "regex"` | the regex finds a match |
| `is = true` / `is = false` | the value is that boolean |

An array value — `args`, say — satisfies a positive operator when any element does, and a negative
one only when no element does. Several operators on one key are ANDed.

A path that resolves to nothing fails the positive operators and passes the negative ones: there is
nothing there to match, and nothing there to violate.

### Actions

| Kind | Fields | Effect |
| --- | --- | --- |
| `deny` | `message` | the call is refused and the message goes to the model as the reason |
| `rewrite` | `replace_head`, `drop_args`, `message` | the call runs with edited input |
| `context` | `message` | the call runs with the message attached |

There is no `ask`. A hook can rewrite tool *input* but cannot switch tools, so redirecting `grep`
to a search tool or `sed` to a read tool can only ever be a deny with guidance; `rm` → `trash` is a
same-tool correction and can be silent.

A rewrite replaces the matched segment's head with `replace_head` and deletes any argument listed
in `drop_args`, splicing into the original command string so everything else survives byte for
byte. It is held back — and the call allowed — when `replace_head` is not on `PATH`, or when the
only match is inside `bash -c '...'` or `$(...)`, where there is no span in the outer string to
edit. That `PATH` gate lives in the engine, not in the rule, so it covers every rewrite ever
written.

## Built-in rules

Compiled into the binary and active with no config, covering every action type so none ships
untested by anything real.

| Name | Action | What it catches |
| --- | --- | --- |
| `fff-over-grep` | deny | `grep`, `rg`, `find`, `git grep` and friends leading a pipeline over an indexed path |
| `read-over-sed` | deny | `sed -n <range>p file`, which is a file read wearing a stream editor's clothes |
| `edit-over-python` | deny | `python3 - <<'PY'`, a whole program written inline to do file surgery |
| `trash-over-rm` | rewrite | `rm` becomes `trash`, recursive and force flags dropped |

`fff-over-grep` leaves three escapes open, each one a case where the guidance would otherwise be
unfollowable: a search after a pipe (`gh pr list | grep foo`) filters output that already exists;
a search that lands outside the workspace, or under `node_modules`, is not something the fff tools
can answer; and a `find` carrying an action primary (`-delete`, `-exec`) traverses in order to act.

## Fail open

Nothing steer does may block a call it did not mean to block. A hook that hard failed would take
out every Bash call in every session, including the ones needed to debug it. So an unreadable
payload, malformed JSON, a broken config, an unknown `--event`, or a panic all exit 0 and emit a
`systemMessage` naming the breakage. The release profile keeps `panic = "unwind"` for that reason —
an aborting panic could not be caught.

Only `steer hook` behaves this way. `check`, `validate`, and `init` are developer tools and report
failures loudly.

## Logging

Every deny, rewrite, and context injection appends a JSON line to
`~/.local/state/steer/steer.jsonl` (or `$XDG_STATE_HOME/steer/steer.jsonl`) with the rule names,
outcome, tool input, agent type, session, and working directory. Allowed calls are not logged. A
failed write is ignored — losing a log line is not a reason to interfere with a tool call.

## License

MIT

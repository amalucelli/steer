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

## How it works

A tool call arrives as JSON on stdin: a tool name and that tool's input. Four stages turn it into a
decision.

**1. Enrichment.** The raw input is copied into a match document with `tool_name` beside it. A Bash
payload gets one more thing: the command line is lexed into `parsed.segments`, so rules can reason
about what is actually being run instead of pattern-matching a string. Other tools pass through
unenriched — a future tool gets its own enricher, not a new config dialect.

**2. Matching.** Every rule is evaluated against that document. One path syntax reaches all of it,
so `file_path` on an Edit payload and `parsed.segments` on a Bash one read the same way.

**3. Resolution.** All matching rules count, and the most restrictive action decides:
**deny > rewrite > context**. File order carries no meaning, so a repo-level config can never
accidentally weaken a global deny. Reasons from every matching rule are concatenated, so the whole
story reaches the model rather than only the rule that happened to win.

**4. Response.** A decision goes back out as JSON, and the harness applies it.

### Bash enrichment

A segment is one pipeline stage with its wrappers peeled:

| Field | |
| --- | --- |
| `head` | basename of the command, so `/usr/bin/grep` and `grep` compare equal |
| `args` | its arguments, unquoted, with redirection targets removed |
| `pipeline_start` | true when the stage runs first in its pipeline |
| `depth` | 0 for the command line, higher inside `bash -c` or `$(...)` |
| `wrappers` | what was peeled to get here |

The split is asymmetric on purpose. `;`, `&&`, `||` and newlines start a new command; `|` only
advances the stage within one. A `grep` after a pipe is filtering something that already ran, which
is legitimate — `pipeline_start` is how a rule tells the two apart.

Peeled as wrappers: leading `VAR=value` assignments, `env`, `sudo`, `time`, `nice`, `command`,
`xargs`, `timeout <duration>`, and the shell keywords `if`, `then`, `elif`, `else`, `while`,
`until`, `do`. `bash -c '...'` (and `sh`, `zsh`, and combined forms like `-lc`) re-enters the lexer
on the script, as does `$(...)`.

An assignment is only peeled when the name before `=` is a shell identifier. A looser test eats
flags like `--include="*.go"` and lets the search they belong to through untouched.

`git` keeps its head but has its own leading options peeled (`-C <path>`, `-c <k=v>`, `--git-dir`,
`--no-pager`, …), so `args.0` is the subcommand whether or not any were given. A rule written for
`git grep` catches `git -C /repo grep` without having to say so.

## Writing a rule

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

Compiled into the binary and active with no config. One per action, so no action type ships
untested by anything real.

| Name | Action | What it catches |
| --- | --- | --- |
| `fff-over-grep` | deny | `grep`, `rg`, `find`, `git grep` and friends leading a pipeline over an indexed path |
| `read-over-sed` | deny | `sed -n <range>p file`, which is a file read wearing a stream editor's clothes |
| `trash-over-rm` | rewrite | `rm` becomes `trash`, recursive and force flags dropped |

`fff-over-grep` leaves three escapes open, each one a case where the guidance would otherwise be
unfollowable: a search after a pipe (`gh pr list | grep foo`) filters output that already exists;
a path outside the index (absolute, home-relative, `node_modules`) is not something the fff tools
can answer; and a `find` carrying an action primary (`-delete`, `-exec`) traverses in order to act.

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

Two files stack on top of the built-ins:

- `~/.config/steer/config.toml` (or `$XDG_CONFIG_HOME/steer/config.toml`) — the base, managed from
  dotfiles.
- `.steer.toml` in the repo, found by walking up from the session's working directory — appends
  rules and disables inherited ones.

Later sources replace an earlier rule of the same name. `disable` switches one off wherever it came
from:

```toml
disable = ["fff-over-grep"]
```

`steer init` writes a commented starter file. `steer validate` reports unknown fields, bad globs and
regexes, duplicate rule names, and a `disable` naming a rule nothing defines — with file and line.

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

## License

MIT

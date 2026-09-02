# Writing rules

```toml
[[rules]]
name = "no-curl"
description = "Network fetches go through the WebFetch tool."
tool = "Bash"  # omit and the rule sees every tool

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["curl", "wget"] }
pipeline_start = { is = true }
args = { none_glob = ["http://localhost*", "http://127.0.0.1*"] }

[rules.action]
kind = "deny"
message = "Use WebFetch — it renders the page and stays in the transcript."

[rules.test]
fires = ["curl https://api.example.com"]
ignores = ["curl http://localhost:8080/health", "gh pr list | curl -X POST"]
```

**A rule fires when any of its `[[rules.match]]` blocks holds.** Blocks are alternatives — the same
shape written more than one way. `fff-over-grep` uses three: `grep`-like, `find`-like, `git grep`.

**A block holds when every condition in it holds against one binding.** The block above asks whether
*one* segment has head `curl` *and* starts its pipeline *and* is not pointed at localhost. Without a
shared binding, `gh pr list | curl -X POST` would match by taking the head from the second segment
and the pipeline position from the first.

Any tool is matchable through its own input fields, so a rule on `Grep` matching
`pattern = { matches = "[a-z][a-zA-Z0-9]*[A-Z]" }` keeps symbol lookups on a language server.

## Tests

`steer validate` runs the `[rules.test]` examples and exits 1 with a file and a line when one fails.

- `fires = [...]` — the rule matches. Only asserts that *something* happened.
- `ignores = [...]` — the rule does not match. Scoped to the one rule, not a claim that steer allows
  the call.
- `rewrites = { "rm -rf a b && echo done" = "trash a b && echo done" }` — pins what a rewrite
  produces, with no `PATH` gate.

`[rules.test]` is a section, so it goes last or it captures the keys after it.

## The match document

Every payload carries `tool_name` plus the tool's own input fields — `command` for Bash, `file_path`
for Read and Edit. A Bash payload also gets `parsed.segments`, one entry per pipeline stage with its
wrappers peeled:

| Field | |
| --- | --- |
| `head` | basename of the command, so `/usr/bin/grep` and `grep` compare equal |
| `args` | its arguments, unquoted, with redirection targets removed |
| `pipeline_start` | true when the stage runs first in its pipeline |
| `in_workspace` | true when the stage reaches into the session's working tree |
| `depth` | 0 for the command line, higher inside `bash -c` or `$(...)` |
| `wrappers` | what was peeled to get here |

Segmentation:

- `;`, `&&`, `||` and newlines start a new segment. `|` only advances the stage within one, so a
  `grep` after a pipe is filtering something that already ran.
- Peeled as wrappers: leading `VAR=value` assignments — only when the name is a shell identifier, so
  `--include="*.go"` survives — plus `env`, `sudo`, `time`, `nice`, `command`, `xargs`,
  `timeout <duration>`, and the keywords `if`, `then`, `elif`, `else`, `while`, `until`, `do`.
- `bash -c '...'` and `$(...)` re-enter the lexer on their script.
- `git` keeps its head but loses its own leading options (`-C <path>`, `-c <k=v>`, `--git-dir`, …),
  so `args.0` is always the subcommand.
- Heredoc bodies are data and produce no segments at all.

`in_workspace`:

- Path-shaped arguments are resolved against the working directory (`~` expanded, `.` and `..`
  folded, no disk access).
- The segment counts as inside when any of them lands there, or when it names no path at all.
- An argument carrying glob or regex metacharacters is what the command is looking for, not where.
- The field is absent when the payload carries no working directory, so a rule asking for it
  declines.

## Conditions

| Operator | Holds when |
| --- | --- |
| `any_of = [...]` | the value equals one of these |
| `none_of = [...]` | it equals none of them |
| `glob = [...]` | it matches one of these glob patterns |
| `none_glob = [...]` | it matches none of them |
| `matches = "regex"` | the regex finds a match |
| `is = true` / `is = false` | the value is that boolean |

- A condition key is a dotted path into the match document. Numeric parts index arrays: `"args.0"` is
  the first argument, which is how `git grep` is told apart from `git commit`.
- A block binds to the whole document unless it names an array with `any = "<path>"` (some element
  satisfies every condition) or `all = "<path>"` (every element does, and an empty array never
  satisfies it).
- An array value — `args`, say — satisfies a positive operator when any element does, and a negative
  one only when no element does.
- Several operators on one key are ANDed.
- A path that resolves to nothing fails the positive operators and passes the negative ones: there is
  nothing there to match, and nothing there to violate.

## Actions

| Kind | Fields | Effect |
| --- | --- | --- |
| `deny` | `message` | the call is refused and the message goes to the model as the reason |
| `rewrite` | `replace_head`, `drop_args`, `add_args`, `message` | the call runs with edited input, or on Codex is denied with the new command as the reason |
| `context` | `message` | the call runs with the message attached |

There is no `ask`. A hook can rewrite tool *input* but cannot switch tools, so redirecting `grep` to
a search tool or `sed` to a read tool can only ever be a deny with guidance; `rm` → `trash` is a
same-tool correction and can be silent.

A rewrite:

- replaces the matched segment's head with `replace_head`, deletes any argument listed in
  `drop_args`, and appends the ones in `add_args` — after the segment's last token but ahead of a
  `--` separator.
- splices into the original command string, so everything else survives byte for byte.
- needs at least one of the three fields; all are optional on their own.
- dedupes nothing. A rule that should not fire twice says so with `none_of`.

Held back — and the call allowed — when `replace_head` is not on `PATH`, or when the only match is
inside `bash -c '...'` or `$(...)`, where there is no span in the outer string to edit. Under Codex a
surviving rewrite comes out as a deny carrying the new command, since Codex accepts `updatedInput`
only alongside `permissionDecision: "allow"`.

## Harness gates

- `agents = ["claude", "codex"]` gates on the harness steer was invoked for; leave it out and the
  rule applies to all of them. Reach for it only when the *matching* is harness-specific.
- When only the message differs, give the action one message per harness under
  `[rules.action.message]`, keyed `claude` and `codex`. Naming a harness there is also the gate.
- Setting both `agents` and a per-harness message is an error, since two gates on one rule can
  disagree.
- `steer hook` detects the harness from the payload, `--agent` overrides it, and when neither
  identifies it the call is allowed with a `systemMessage` asking for `--agent` rather than guessing.
- `steer check` takes no harness — it evaluates every rule whatever its `agents` gate says.

## Codex

- The hook registration goes in `~/.codex/hooks.json`, a `[hooks]` table in `~/.codex/config.toml`,
  or `.codex/hooks.json` in the repo. The harness is read off the payload, so no `--agent codex`.
- Never set `"async": true` — an async hook cannot block, approve, or rewrite, so every rule quietly
  becomes a no-op.
- Codex hash-tracks the registered command for trust, so changing the string forces a re-review
  through `/hooks`.
- None of this is tested against a running Codex.

## Config sources

Each source stacks on the one before:

1. Built-ins, compiled into the binary.
2. `~/.config/steer/config.toml`, honoring `$XDG_CONFIG_HOME`.
3. `.steer.toml`, found by walking up from the session's working directory.

A later source replaces an earlier rule of the same name, and `disable = ["fff-over-grep"]` switches
one off wherever it came from. What a repo file cannot do is quietly soften a rule it does not name:
every matching rule is evaluated and the strongest action wins, so a `context` rule beside an
inherited `deny` still denies. `PostToolUse` accepts only `context` rules, since denying or rewriting
a call that already ran means nothing.

`steer validate` prints the whole stack — every source, the rules it declares, what each one tests,
and what became of it once the sources collapsed:

```
source    built-in
rule      fff-over-grep          deny · Bash · claude
  match   any parsed.segments  head=[grep,egrep,rg,ag,ack] args!~[node_modules*] in_workspace pipeline_start
  fires   grep -rn foo src
  ignores gh pr list | grep foo
rule      edit-over-python       deny · Bash · claude, codex
          disabled by /home/me/.config/steer/config.toml
rule      trash-over-rm          rewrite → trash · Bash · any agent
  drops   -r -R -f -rf --recursive --force
  rewrite rm -rf dist  →  trash dist

source    /home/me/.config/steer/config.toml
disable   edit-over-python

ok        3 rules
```

`disabled by`, `replaced by`, and `held:` are the three ways a rule that is written down is not a
rule that runs — the last being a rewrite whose replacement is missing from PATH. The same pass
reports unknown fields, bad globs and regexes, duplicate rule names, and a `disable` naming a rule
nothing defines, with file and line, and exit 1.

## Fail open

An unreadable payload, malformed JSON, a broken config, an unknown `--event` or `--agent`, an
unrecognised flag, an unidentifiable harness, or a panic all exit 0 and emit a `systemMessage` naming
the breakage. The message goes both at the top level and nested inside `hookSpecificOutput`, since
the harnesses read it in different places, and the release profile keeps `panic = "unwind"` so a
panic can be caught at all. Only `steer hook` behaves this way; `check`, `validate`, and `init`
report failures loudly.

## The log

Every deny, rewrite, and context injection appends a JSON line to `~/.local/state/steer/steer.jsonl`
(`$XDG_STATE_HOME` honored) with the rule names, outcome, tool input, harness, agent type, session,
and working directory. A failed write is ignored — losing a log line is not a reason to interfere
with a tool call.

Allowed **Bash** calls are logged too, with an `allow` outcome and no rule names: a rule the model
worked around leaves a deny followed seconds later by a command that got through, and the second line
is the only one naming the spelling the rule missed. Allowed calls to other tools are not logged,
which keeps Edit and Write payloads — whole file contents — out of the file.

### replay

`steer replay` runs the current rules over every logged command and prints only what they would now
answer differently, in two buckets — `would now be stopped` and `would now go through` — with the
rule and a sample of the calls under each. The count says how wide a rule reaches and the sample says
whether it is right.

### suggest

`steer suggest` reports what the log says is missing:

- An **escape** is a deny and the command that got through right behind it — same session, inside a
  minute, sharing an operand or the leading command.
- A **shape** is the leading command of calls nothing caught, counted.

A rule denies on what it names in `head`, so a pair whose follow-up leads with something else is a
question rather than a finding — as likely the model taking the guidance as routing around it. Those
are counted in one `weak` line that `--all` expands, while `--strong` prints only the findings,
dropping the shapes. Where the rule does name the command, `signal` reports the condition that let
the call through: `in_workspace` or `pipeline_start` is usually the escape the rule documents, an
argument usually a spelling it misses.

`--draft <name>` turns one finding into TOML and prints nothing else:

- `steer suggest --draft nl >> ~/.config/steer/config.toml` appends a starter rule for that shape
  with the logged call already in `fires`.
- Given a rule name, it redrafts that whole rule with the escaped shape as another block.
- A drafted block matches on the command name alone, so every draft ends by pointing at `replay`.
- On a weak signal it declines and names the two edits it could not choose between.

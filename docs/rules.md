# Writing rules

```toml
[[rules]]
name = "no-curl"
description = "Network fetches go through the WebFetch tool."
tool = "shell"  # omit and the rule sees every tool
agents = ["claude"]  # the message names a Claude Code tool

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

Any tool is matchable through its own input fields, so a rule on `search` matching
`pattern = { matches = "[a-z][a-zA-Z0-9]*[A-Z]" }` keeps symbol lookups on a language server.

## Tests

`steer validate` runs the `[rules.test]` examples and exits 1 with a file and a line when one fails.

- `fires = [...]` — the rule matches. Only asserts that *something* happened.
- `ignores = [...]` — the rule does not match. Scoped to the one rule, not a claim that steer allows
  the call.
- `rewrites = { "rm -rf a b && echo done" = "trash a b && echo done" }` — pins what a rewrite
  produces, with no `PATH` gate.

`[rules.test]` is a section, so it goes last or it captures the keys after it.

Examples are shell command lines. A rule gated on another tool cannot declare any — doing so is
reported as a problem rather than silently passing — so a rule on `read` or `fetch` is compiled and
checked for bad globs and unknown fields, but nothing proves it fires.

## The match document

Every payload carries `tool_name` plus the tool's own input fields, in one vocabulary whatever
harness sent it. The tools are `shell`, `read`, `edit`, `write`, `search`, `find` and `fetch`, and
each harness's own names are mapped onto them on the way in: `Bash`, `run_shell_command`,
`execute_command` and Windsurf's `pre_run_command` all reach a rule as `shell`. A name no harness
maps arrives unchanged, which is what keeps `NotebookEdit` and an MCP tool addressable — while
naming one that is mapped, `tool = "Bash"`, is reported as a rule that can never fire rather than
left to match nothing.

Two input fields are canonical the same way. `command` carries the shell command line wherever the
harness keeps it — Amp's `cmd`, Windsurf's `command_line`, Antigravity's `args.CommandLine` — and
`path` carries the file a file tool acts on. `path` is renamed only for the six harnesses that
publish a file-tool schema; the other ten publish none, so nothing is renamed there and a rule
matching `path` reaches them only if their payload already spells it that way. Guessing the name
instead would produce a rule that matches nothing and says so nowhere.

A shell payload also gets `parsed.segments`, one entry per pipeline stage with its wrappers peeled:

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
| `rewrite` | `replace_head`, `drop_args`, `add_args`, `message` | the call runs with edited input, or is denied with the new command as the reason where the harness takes none |
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
inside `bash -c '...'` or `$(...)`, where there is no span in the outer string to edit.

On the five harnesses that accept no edited tool input a surviving rewrite comes out as a deny
carrying the new command: guidance rather than a silent correction, and stricter than the edited
call it stands in for, which is the only direction a degradation may go. Codex is the illustration:
it accepts `updatedInput` only alongside
`permissionDecision: "allow"`, so there is no way to edit the call and still route it through the
user. A `context` rule has no weaker form — a note is already the mildest thing steer does — so on a
harness that takes none it is dropped rather than degraded, and `validate` says which and why.

## Harness gates

- `agents = ["claude", "codex"]` gates on the harness steer was invoked for, named as `--agent`
  names it; leave it out and the rule applies to all of them. Reach for it only when the *matching*
  is harness-specific.
- When only the message differs, give the action one message per harness under
  `[rules.action.message]`, keyed `claude` and `codex`. Naming a harness there is also the gate: a
  harness the table skips does not get the rule.
- `default` in that table lifts the gate — it covers every harness, and a key naming one overrides it
  there. Message prose may write `{shell}`, `{read}`, `{edit}`, `{write}` or `{search}`, each rendered
  as the name the target harness's model can call: `{edit}` is `Edit` under Claude Code and
  `apply_patch` under Codex. That is what lets one `default` still name a tool rather than a category.
- `requires = ["read", "search"]` gates on capability instead: the rule reaches a harness only where
  every tool it names is one that harness has. Codex and Goose have no read and no search tool of
  their own, so a rule pointing at one skips them and reaches the other fourteen — including whatever
  ships next, which is what listing harnesses cannot do.
- A message writing a token has to require that tool, and `validate` says so when it does not. Without
  it a rule writing `{read}` denies a shell command by recommending one wherever the harness has no
  read tool, which is the failure the gate exists for.
- Setting both `agents` and a message table that gates is an error, since two gates on one rule can
  disagree. `agents` beside a table carrying `default` is fine — that is a gate plus the copy the
  gated harnesses read. `agents` and `requires` are independent and both have to pass; a combination
  that leaves no harness standing is an error too.
- Every registration names its harness with `--agent`, and a payload arriving without one is allowed
  through with a `systemMessage` asking for it. Which harness sent it is never inferred from its
  shape: harnesses copy each other's envelopes, so a payload that looks like Claude Code's is not
  evidence it is one, and the wrong descriptor is a whole ruleset going quietly wrong.
- `steer check` takes no harness — it evaluates every rule whatever its `agents` gate says, and
  prints every copy of a message with its tokens unrendered.

## Harnesses

steer speaks to sixteen. What differs between them is where the registration goes, whether the
harness will accept an edited tool input, and whether it will take a note before the call runs.
Everything else — the rule language, the match document, the strongest-action-wins resolution — is
the same everywhere.

| `--agent` | Registered in | A rewrite | A `context` rule |
| --- | --- | --- | --- |
| `claude` | `~/.claude/settings.json` | edits the call | arrives before the call |
| `codex` | `~/.codex/hooks.json`, a `[hooks]` table in `~/.codex/config.toml`, or `.codex/hooks.json` | denies, carrying the command | arrives before the call |
| `qwen` | its own `settings.json` | edits the call | arrives before the call |
| `continue` | Claude Code's settings files, which it reads itself | edits the call | arrives before the call |
| `junie` | `~/.junie/` | edits the call | arrives before the call |
| `gemini` | its own `settings.json`, under `BeforeTool` | edits the call | is dropped |
| `cursor` | `.cursor/hooks.json` | edits the call | is dropped |
| `copilot` | `~/.copilot/hooks/` | edits the call | is dropped |
| `crush` | `crush.json` | edits the call | arrives before the call |
| `cline` | `.clinerules/hooks/PreToolUse`, an executable rather than a config entry | denies, carrying the command | arrives before the call |
| `goose` | its own hooks config | denies, carrying the command | is dropped |
| `windsurf` | its own hooks config, one entry per action | denies, carrying the command | is dropped |
| `antigravity` | `.agents/hooks.json` or `~/.gemini/config/hooks.json` | denies, carrying the command | is dropped |
| `opencode` | `.opencode/plugins/steer.js`, written by `steer init` | edits the call | is dropped |
| `pi` | `.pi/extensions/steer.ts`, written by `steer init` | edits the call | is dropped |
| `amp` | `.amp/plugins/steer.js`, written by `steer init` | edits the call | is dropped |

What steer encodes per harness is the payload it sends and the answer it reads; the registration
paths above are what each harness's own documentation says, and Goose's and Windsurf's are left
unnamed because nothing in this repository records them. The last three load a plugin into their own
process rather than spawning one, so `steer init --agent <name>` writes it and the payload steer
reads there is the plugin's, forwarded as the harness handed it over.

**Codex** registrations must never set `"async": true` — an async hook cannot block, approve, or
rewrite, so every rule quietly becomes a no-op. Codex also hash-tracks the registered command for
trust, so changing the string forces a re-review through `/hooks`.

**Continue.dev** reads Claude Code's settings files directly, so a hand-written Claude registration
fires under it with `--agent claude`. That is harmless while the two contracts match, and it is
worth registering Continue explicitly anyway, for the day they stop matching.

**Cursor** has no edit tool: an edit and a create both arrive as `Write` and reach a rule as `edit`,
so `tool = "write"` never fires there and a rule that tells changing a file from making one cannot
tell them apart. It is registered natively rather than through `~/.claude/settings.json`, which
Cursor also reads, because Claude Code's deny reason maps onto the field Cursor shows the person and
nothing on the Claude side maps onto the one the model reads.

**Copilot CLI** documents `toolArgs` as an object and ships it as a string of JSON. steer decodes it
on the way in; a reader that trusts the documentation finds no command and lets every rule pass.

**Windsurf** registers one hook per action rather than per tool — `pre_run_command`,
`pre_read_code`, `pre_write_code` — and the action is the tool identity, since the payload carries
no tool name at all. It answers on the exit code with the reason on stderr and reads nothing on
stdout. Whether it shows stderr on an allowed call is undocumented, so a note about a broken steer
config may reach nobody there.

**Goose**'s hooks reference names a shell tool and an editor and no read or search tool, and the
descriptor follows it rather than routing a read through the shell — so a rule requiring either
skips Goose instead of denying a shell command by recommending one. Whether Goose accepts an edited
input is not documented either way, and absent is the safe reading.

**Amp**'s deep mode runs the same shell under a second name, `shell_command`, which keeps its
command in `command` rather than the `cmd` the ordinary shell tool uses. One command field per
harness, so that name is left unmapped and shell rules do not fire in deep mode.

**pi** loads a project's extensions only once the project is trusted, and answers no trust prompt in
`-p` or the other non-interactive modes. An extension that appears to do nothing there is usually
that.

Several harnesses also read an exit code — 2 blocks under Junie and Gemini CLI, and Crush's 49 halts
the turn outright, which is stronger than a deny and has no rule that asks for it. steer exits 0 on
all of them and answers in the JSON, which is the path that also carries a reason; Windsurf is the
exception, having no other channel.

## Config sources

Each source stacks on the one before:

1. Built-ins, compiled into the binary.
2. `~/.config/steer/config.toml`, honoring `$XDG_CONFIG_HOME`.
3. `.steer.toml`, found by walking up from the session's working directory.

`steer check --config <path>` and `steer validate --config <path>` set that aside and evaluate the
named file alone, which is how a rule gets read before it is adopted. `builtins = false` is inert
there — nothing loaded them — and a `disable` naming a rule the file does not define is the same
error it always was, since the disable is answered by what loaded. `steer hook` has no such flag.

A later source replaces an earlier rule of the same name, and `disable = ["fff-over-grep"]` switches
one off wherever it came from. What a repo file cannot do is quietly soften a rule it does not name:
every matching rule is evaluated and the strongest action wins, so a `context` rule beside an
inherited `deny` still denies. `PostToolUse` accepts only `context` rules, since denying or rewriting
a call that already ran means nothing.

`steer validate` prints the whole stack — every source, the rules it declares, what each one tests,
and what became of it once the sources collapsed:

```
source    built-in
rule      fff-over-grep            deny · shell · claude · 15 dropped, not in `agents`
          Shell searches over indexed paths belong to the fff MCP tools.
  match   any parsed.segments  head=[grep,egrep,fgrep,rg,ag,ack,ack-grep,ugrep] args!~[node_modules*,*/node_modules*] in_workspace pipeline_start
  fires   grep -rn foo src
  ignores gh pr list | grep foo
rule      read-over-shell-pager    deny · shell · 14 agents · codex, goose: dropped, no read tool
          Shell file reads and line-range pagers belong to a read tool.
  match   any parsed.segments  head=[sed,gsed] args=[-n,-ne,-nE,-En,--quiet,--silent] pipeline_start
  fires   sed -n 800,900p src/rules.rs
rule      edit-over-python         deny · shell · any agent
          disabled by /home/me/.config/steer/config.toml
          Inline Python programs fed to stdin belong to a real edit tool.
rule      trash-over-rm            rewrite → trash · shell · 11 agents · codex, cline, goose, windsurf, antigravity: deny carrying the command
          Deletes go to the trash so they stay recoverable.
  drops   -r -R -f -rf -fr -Rf -fR -rF --recursive --force
  match   any parsed.segments  head=rm
  rewrite rm -rf dist  →  trash dist

source    /home/me/.config/steer/config.toml
disable   edit-over-python
rule      no-curl  deny · Bash · any agent
          Network fetches go through the fetch tool.
  match   any parsed.segments  head=curl

problem   /home/me/.config/steer/config.toml:6:8: `tool = "Bash"` can never match; ingest renames it to `shell`
```

Trimmed to four of the built-ins; a run prints every rule of every source, and closes with
`ok <n> rules` where this one closes with a problem.

After the tool comes the rule's verdict for every harness, in three groups: the ones it reaches, the
ones it reaches in a weaker form, and the ones it never reaches, with the reason. `any agent` is the
ordinary case. A group of more than five is counted rather than named, so the harnesses a rule
treats unusually are the ones the line spells out — a rule vanishing for a harness nobody was
thinking about is the worst thing that can happen to a ruleset, and a roll call of the fifteen that
behave is what buries it.

That verdict weighs the rule's gates and each harness's capabilities, not its conditions — which is
why `no-curl` above reads `any agent` on the same line its `tool = "Bash"` gate is reported as
matching nothing. The two answer different questions, and a rule wants both to come out right.

`disabled by`, `replaced by`, and `held:` are the three ways a rule that is written down is not a
rule that runs — the last being a rewrite whose replacement is missing from PATH. The same pass
reports unknown fields, bad globs and regexes, duplicate rule names, a `disable` naming a rule
nothing defines, and any name ingest renames before matching — `tool = "Bash"` can never match,
because the payload's `Bash` is `shell` by the time a rule sees it, and neither can a condition on
`file_path`, which arrives as `path`. All with file and line, and exit 1. The hook path reports that
last one as a `systemMessage` and lets the call through instead, since a config error that blocked
every tool call would block the ones needed to fix it.

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

Allowed **shell** calls are logged too, with an `allow` outcome and no rule names: a rule the model
worked around leaves a deny followed seconds later by a command that got through, and the second line
is the only one naming the spelling the rule missed. Allowed calls to other tools are not logged,
which keeps edit and write payloads — whole file contents — out of the file.

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

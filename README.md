# steer

**A rule engine that sits in front of an agent's tool calls.** It sees each call before it runs and
either **denies** it with guidance the model reads, **rewrites** its input in place, or lets it
through with **context** attached.

It exists because a harness can outrank you: Claude Code's auto mode injects a system directive to
search with shell `grep` and read with `sed -n`, it beats anything in `CLAUDE.md`, and a hook is the
last layer that still gets to decide.

```
$ steer check 'cd build && rm -rf dist'
command   cd build && rm -rf dist
segments
  head=cd args=["build"] pipeline_start=true in_workspace=true depth=0
  head=rm args=["-rf", "dist"] pipeline_start=true in_workspace=true depth=0
matched   trash-over-rm  (block 0, parsed.segments[1])
action    rewrite
rewrite   cd build && trash dist
message
  steer: `rm` becomes `trash` so the delete stays recoverable.
```

## Install

```sh
brew install --cask amalucelli/tap/steer
```

Or from source: `cargo install --path . --root ~/.local`. Then register it in
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "steer hook --event PreToolUse" }] }
    ]
  }
}
```

No config file is needed — the built-in rules are compiled into the binary and active on install.
Codex takes the same block from `~/.codex/hooks.json`; see [docs/rules.md](docs/rules.md#codex) for
what differs there.

## Commands

```
steer hook --event PreToolUse|PostToolUse [--agent claude|codex]  # decide on a payload from stdin
steer check '<command>'                                           # dry-run a command through the rules
steer replay [--since <age>]                                      # what the rules would now answer differently
steer suggest [--since <age>] [--strong|--all] [--draft <name>]   # escapes and uncaught shapes from the log
steer validate                                                    # the effective ruleset and its problems
steer init                                                        # write a starter global config
```

Everything from `check`'s first positional word on is the command line, so `steer check -la` reaches
the rules with its flags intact. It exits 1 when the command would be denied, and prints a `nearest`
block when nothing matched: the rules that came closest, each condition ticked or crossed with the
actual value.

## Config

Rules come from three places, each stacking on the one before:

- **Built-ins**, compiled into the binary and active with no config file at all.
- **`~/.config/steer/config.toml`** — your base, the one to keep in dotfiles. `steer init` writes a
  commented starter there.
- **`.steer.toml` in the repo**, found by walking up from the session's working directory.

A later source replaces an earlier rule of the same name, and `disable = ["fff-over-grep"]` switches
one off wherever it came from. `steer validate` prints the whole stack — every source, the rules it
declares, what each one tests, and what became of it once the sources collapsed — along with unknown
fields, bad globs, duplicate names, and failing tests, with file and line, and exit 1.

## Write a rule

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

A rule fires when any of its `[[rules.match]]` blocks holds, and a block holds when every condition
in it holds against one binding. Every matching rule is evaluated and the strongest action wins —
**deny > rewrite > context** — so file order never changes the outcome. `steer validate` runs the
`[rules.test]` examples and fails when one stops firing.

[docs/rules.md](docs/rules.md) has the rest: the match document, the condition operators, what each
action does, and the harness gates.

## Built-in rules

| Name | Action | Agents | What it catches |
| --- | --- | --- | --- |
| `fff-over-grep` | deny | claude | `grep`, `rg`, `find`, `git grep` and friends leading a pipeline over an indexed path |
| `read-over-shell-pager` | deny | claude | `sed -n`, `cat -n`, `cat file \| head`, `awk 'NR>=x'` — the family of ways to ask for a line range from a file |
| `edit-over-python` | deny | all | `python3 - <<'PY'`, a whole program written inline to do file surgery |
| `trash-over-rm` | rewrite | all | `rm` becomes `trash`, recursive and force flags dropped |

Two are Claude-only because of where their messages point: Codex has no read tool and no fff, and a
deny naming a tool the model cannot call is worse than no rule.

## Log

Every deny, rewrite, and context injection — plus every allowed **Bash** call — appends a JSON line
to `~/.local/state/steer/steer.jsonl`. `steer replay` runs the current rules over that log and prints
only what they would now answer differently, which is how a rule gets tested before it ships.
`steer suggest` reports what the log says is missing: a deny and the command that got through right
behind it, and the leading commands of calls nothing caught.

## License

MIT

# steer

**steer enforces rules on what a coding agent runs.** Agents like Claude Code, Codex and Cursor work
through **tool calls**: run a shell command, read a file, edit one. steer checks each call before it
runs and can block it, change it, or let it through.

## The problem

You can tell an agent how to work in `CLAUDE.md` or `AGENTS.md`, but that's text in a prompt, and
other text can outrank it. Claude Code's auto mode, for example, tells the model to search with
`grep` and read files with `sed -n`, and that wins over what you wrote. Instructions don't reliably
stop an agent from deleting with `rm -rf`, force-pushing, or opening `vim` in a session that has no
terminal.

Most agents also support **hooks**: a program the agent runs before every tool call, whose answer
it has to follow. A hook can't be argued with, so that's where steer puts your rules.

## How it works

You register steer as the agent's pre-tool hook. For each call, it checks your rules and answers in
one of three ways:

- **deny**: the call doesn't run, and the model gets your message saying what to do instead.
- **rewrite**: the call runs with its input changed, so `rm -rf dist` runs as `trash dist`.
- **context**: the call runs, and the model gets a note with it.

When Claude Code tries to read a file with `sed -n 1,50p src/main.rs`, the call is denied and the
model reads:

> Use the Read tool to read a file. It takes `offset` and `limit` for a window and returns numbered
> lines, so there is no need to page one with a shell command.

`steer check` shows what steer would do with a command, without an agent involved:

```js
$ steer check 'cd build && rm -rf dist'
command   cd build && rm -rf dist
cwd       /home/me/src/app
segments
  head=cd args=["build"] pipeline_start=true in_workspace=true depth=0
  head=rm args=["-rf", "dist"] pipeline_start=true in_workspace=true depth=0
matched   trash-over-rm  (block 0, parsed.segments[1])
action    rewrite
rewrite   cd build && trash dist
message
  steer: `rm` becomes `trash` so the delete stays recoverable.
```

steer splits the command into **segments**, one per program, so the `rm` after `cd build &&` is
checked on its own. The `trash-over-rm` rule matched it and rewrote the command.

## Write a rule

Rules are TOML. This is `trash-over-rm`, the built-in rule from the example above:

```toml
[[rules]]
name = "trash-over-rm"
description = "Deletes go to the trash so they stay recoverable."
tool = "shell"

[[rules.match]]
any = "parsed.segments"
head = { any_of = ["rm"] }

[rules.action]
kind = "rewrite"
replace_head = "trash"
drop_args = ["-r", "-R", "-f", "-rf", "-fr", "-Rf", "-fR", "-rF", "--recursive", "--force"]
message = "steer: `rm` becomes `trash` so the delete stays recoverable."

[rules.test]
ignores = ["trash dist", "git rm --cached secrets.env"]
rewrites = { "rm -rf dist" = "trash dist", "cd build && rm -f out.o" = "cd build && trash out.o", "rm -rf a b && echo done" = "trash a b && echo done" }
```

A rule names the tool it applies to, what to match, and what to do. `head` is the program that starts
a segment, so this matches `rm` after `cd build &&` but not the `rm` in `git rm`. A rule fires when
any of its `[[rules.match]]` blocks matches.

`[rules.test]` holds example commands. `steer validate` runs them and fails when a rule stops doing
what its examples say.

When several rules match one call, the strongest action wins: **deny > rewrite > context**. The order
of rules in a file never changes the outcome.

[docs/rules.md](docs/rules.md) covers the match document, condition operators, actions, and harness
gates.

## Examples

[examples/](examples/) has thirty-two rules to copy from, grouped by
[secrets](examples/secrets.toml), [network](examples/network.toml),
[destructive operations](examples/destructive.toml), [outward actions](examples/outward.toml)
like publishing or merging, [session hazards](examples/session.toml), and
[workflow](examples/workflow.toml). None are active until you copy them into your config. To try a
file first, `--config` loads that file and nothing else:

```sh
steer check --config examples/destructive.toml 'git reset --hard origin/main'
steer validate --config examples/destructive.toml
```

## Install

```sh
brew install --cask amalucelli/tap/steer
```

Or from source: `cargo install --path . --root ~/.local`. Then register steer as a hook in your
agent. For Claude Code, add this to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "steer hook --event PreToolUse --agent claude" }] }
    ]
  }
}
```

That's all the setup. The [built-in rules](#built-in-rules) are active as soon as the hook is
registered, with no config file.

steer works with sixteen agents. Most run a hook command, and take the same line with their own
`--agent` name. OpenCode, pi and Amp load a plugin instead, which `steer init --agent <name>` writes.

| | `--agent` |
| --- | --- |
| **Command hook** | `claude`, `codex`, `qwen`, `continue`, `junie`, `gemini`, `cursor`, `copilot`, `crush`, `cline`, `goose`, `windsurf`, `antigravity` |
| **Plugin** | `opencode`, `pi`, `amp` |

Always pass `--agent`. Agents copy each other's hook formats, so steer won't guess which one is
calling; without the flag it lets every call through with a warning. `steer init --force` replaces a
plugin written by an older steer. [docs/rules.md](docs/rules.md#harnesses) lists where each one is
registered and what it supports.

## Built-in rules

These are on by default. Most stop the agent from using a shell command where it has a better tool;
the rest stop something that can't be undone, or a program that hangs without a terminal.

| Name | Action | Agents | What it catches |
| --- | --- | --- | --- |
| `fff-over-grep` | deny | claude | `grep`, `rg`, `find`, `git grep` and friends leading a pipeline over an indexed path |
| `read-over-shell-pager` | deny | all with a read tool | `sed -n`, `cat -n`, `cat file \| head`, `awk 'NR>=x'` — the family of ways to ask for a line range from a file |
| `edit-over-python` | deny | all | `python3 - <<'PY'`, a whole program written inline to do file surgery |
| `edit-over-inplace` | deny | all | `sed -i`, `perl -pi`, `awk -i inplace` — the same file surgery written as a flag |
| `trash-over-rm` | rewrite | all | `rm` becomes `trash`, recursive and force flags dropped |
| `no-pipe-to-shell` | deny | all | `curl … \| sh`, a script executed before anything reads it |
| `force-with-lease` | rewrite | all | `git push --force` becomes `--force-with-lease` |
| `no-interactive-commands` | deny | all | `git rebase -i`, `git add -p`, `vim`, `less`, a bare `ssh` — programs that wait for a terminal that isn't there |

`fff-over-grep` sends Claude Code to the fff MCP search server; disable it if you don't use fff.
Turn any rule off with `disable = ["<name>"]` in your config. Some agents can't change a call's
input, so on those a rewrite becomes a deny that gives the model the corrected command.

## Config

Rules come from three places. A rule in a later one replaces a rule with the same name from an
earlier one:

1. Built-ins.
2. `~/.config/steer/config.toml`, your base. `steer init` writes a starter.
3. `.steer.toml` in the repo, found by walking up from the working directory.

`builtins = false` turns off all the built-ins. `steer validate` prints the rules that end up active
and reports unknown fields, bad globs, duplicate names, and failing tests with file and line. See
[docs/rules.md](docs/rules.md#config-sources).

## Commands

```sh
# decide on a payload from stdin
steer hook --event PreToolUse|PostToolUse [--agent <harness>]

# dry-run a command through the rules
steer check [--config <path>] '<command>'

# what the rules would now answer differently
steer replay [--since <age>]

# escapes and uncaught shapes from the log
steer suggest [--since <age>] [--all] [--apply|--draft <name>]

# the effective ruleset and its problems
steer validate [--config <path>]

# write a starter global config, or a harness's plugin file
steer init [--agent <harness>] [--force]
```

`check` exits 1 when the command would be denied. When nothing matched, it prints the rules that came
closest, with each condition marked pass or fail. `--config` must come before the command.

`hook` is what the agent runs; you only call the others yourself.

steer logs every deny, rewrite and context note, plus every allowed shell call, to
`~/.local/state/steer/steer.jsonl`. `replay` runs your current rules over that log, so you can see
what a rule change would do before relying on it. `suggest` finds commands the agent ran right after
a deny to get around it. `--apply` marks those as accepted in your config so they stop being
reported, without changing what the rule matches. `--draft <rule>` prints a rule change that would
catch them instead.
[docs/rules.md](docs/rules.md#the-log) has the details.

## License

MIT

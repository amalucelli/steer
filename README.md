# steer

**A rule engine that sits in front of an agent's tool calls.** It sees each call before it runs and
either **denies** it with guidance the model reads, **rewrites** its input in place, or lets it
through with **context** attached.

It exists because a harness can outrank you: Claude Code's auto mode injects a system directive to
search with shell `grep` and read with `sed -n`, it beats anything in `CLAUDE.md`, and a hook is the
last layer that still gets to decide.

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

## Write a rule

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

A rule fires when any of its `[[rules.match]]` blocks holds, and a block holds when every condition
in it holds against one binding. Every matching rule is evaluated and the strongest action wins —
**deny > rewrite > context** — so file order never changes the outcome. `steer validate` runs the
`[rules.test]` examples and fails when one stops firing.

[docs/rules.md](docs/rules.md) has the rest: the match document, the condition operators, what each
action does, and the harness gates.

## Examples

[examples/](examples/) is a menu of thirty-two rules to copy from, none of them active until you
do:

- [secrets.toml](examples/secrets.toml) — reading a `.env` or a private key into the transcript,
  dumping the environment, a token in argv or in a URL, a command whose whole job is printing a
  credential, committing a key.
- [network.toml](examples/network.toml) — `curl -k` and the environment variables that mean the
  same thing, a registry override, a fetch outside the host allowlist, an install with nothing
  pinned.
- [destructive.toml](examples/destructive.toml) — discarding uncommitted work, `sudo`, docker
  volumes, kubectl and psql pointed at production, `terraform apply -auto-approve`.
- [outward.toml](examples/outward.toml) — publishing a package, merging a pull request, cutting a
  release, commenting under the user's name, moving a published tag, deploying.
- [session.toml](examples/session.toml) — an `export` or `cd` that ends with the call, a sleep that
  spends the time budget, a detached process nothing will stop, a setup wizard with no stdin.
- [workflow.toml](examples/workflow.toml) — staying inside the working tree, who gets to stage a
  commit, `--no-verify`, global git config, dev servers, hand-edited lockfiles, whole-suite test
  runs.

Each rule carries the reasoning that produced it: what it lets through on purpose, and where it
stops working. `--config` runs a file on its own, in place of the built-ins and your config, which
is how you try one before taking it:

```sh
steer check --config examples/destructive.toml 'git reset --hard origin/main'
steer validate --config examples/destructive.toml
```

## Install

```sh
brew install --cask amalucelli/tap/steer
```

Or from source: `cargo install --path . --root ~/.local`. Then register it. Under Claude Code that
is `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "steer hook --event PreToolUse --agent claude" }] }
    ]
  }
}
```

No config file is needed — the built-in rules are compiled into the binary and active on install.

Twelve more harnesses take that same command in their own pre-tool hook file, with their own name:
`steer hook --event PreToolUse --agent codex`. Every registration names its harness, and one that
names none is allowed through with a `systemMessage` asking for it — harnesses copy each other's
payload shapes, so steer never guesses which one it is talking to.

| | `--agent` |
| --- | --- |
| **Command hook** | `claude`, `codex`, `qwen`, `continue`, `junie`, `gemini`, `cursor`, `copilot`, `crush`, `cline`, `goose`, `windsurf`, `antigravity` |
| **Plugin** | `opencode`, `pi`, `amp` |

[docs/rules.md](docs/rules.md#harnesses) has the file each one is registered in, whether it accepts
an edited tool input, and whether it will take a note before the call runs.

OpenCode, pi and Amp load a plugin into their own process instead of spawning one, so steer writes
theirs:

```sh
steer init --agent opencode   # or pi, or amp
```

It refuses to overwrite a file that is already there. `--force` is how an upgraded steer replaces
the plugin an older one wrote, which otherwise keeps talking to a binary it no longer matches.

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

Everything from `check`'s first positional word on is the command line, so `steer check -la` reaches
the rules with its flags intact — which is also why `--config` has to come before the command. It
exits 1 when the command would be denied, and prints a `nearest` block when nothing matched: the
rules that came closest, each condition ticked or crossed with the actual value.

`--config <path>` replaces the whole stack with that one file: no built-ins, no
`~/.config/steer/config.toml`, no repo `.steer.toml`. It is how a rule gets read before it is
adopted, and `validate` runs the file's `[rules.test]` examples the same way it runs everyone
else's.

## Config

Rules come from three places, each stacking on the one before:

- **Built-ins**, compiled into the binary and active with no config file at all.
- **`~/.config/steer/config.toml`** — your base, the one to keep in dotfiles. `steer init` writes a
  commented starter there.
- **`.steer.toml` in the repo**, found by walking up from the session's working directory.

A later source replaces an earlier rule of the same name, `disable = ["fff-over-grep"]` switches one
off wherever it came from, and `builtins = false` starts from none of them — a `disable` list naming
them all is complete only until the next built-in ships. `steer validate` prints the whole stack —
every source, the rules it declares, what each one tests, and what became of it once the sources
collapsed — along with unknown fields, bad globs, duplicate names, and failing tests, with file and
line, and exit 1.

## Built-in rules

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

The first five are about tool routing: a shell command standing in for something the harness does
better. The last three are not. Two of them stop an operation that cannot be undone, and the third
is a fact about the environment rather than an opinion — a hook-driven session has no terminal, so
an interactive program hangs until it is killed.

`fff-over-grep` is Claude-only because of where its message points: fff is an MCP server the user
configured rather than a tool any harness ships, so there is nothing to name elsewhere.
`read-over-shell-pager` names a read tool instead of a vendor's, so it applies wherever the harness
has one — everywhere but Codex and Goose, which have none, and a deny naming a tool the model cannot
call is worse than no rule.

The two rewrites arrive as a deny carrying the corrected command on the five harnesses that accept
no edited tool input — Codex, Cline, Goose, Windsurf and Antigravity — which reads as guidance
rather than as a silent correction.

## Log

Every deny, rewrite, and context injection — plus every allowed **shell** call — appends a JSON line
to `~/.local/state/steer/steer.jsonl`. `steer replay` runs the current rules over that log and prints
only what they would now answer differently, which is how a rule gets tested before it ships.
`steer suggest` reports what the log says is missing: a deny and the command that got through right
behind it, and the leading commands of calls nothing caught. It sorts those pairs first — `closed`
where the rules now answer them, `by design` where the rule declares that escape in its own
`ignores`, `weak` where the denying rule never named the command that ran — and what is left prints
as a `fix`, one line per rule and condition. `--apply` writes those to your config as escapes their
rules allow, an `[[amend]]` entry that changes no matching and that `validate` holds from then on.
`--draft <rule>` prints the block that closes one instead, which is a rule edit you make.

## License

MIT

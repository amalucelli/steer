// The built-in rules, driven through the real binary the way Claude Code drives
// it: a hook payload on stdin, `hookSpecificOutput` on stdout.
//
// One test binary, split by subject.

mod builtins;
mod cli;
mod config;
mod harness;
mod heredoc;
mod hook;
mod replay;
mod rewrite;
mod sandbox;

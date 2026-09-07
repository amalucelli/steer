// The plugin files for the harnesses steer cannot be registered into.
//
// OpenCode, pi and Amp never spawn a process to intercept a tool call — they
// load a module into their own and call it — so something in-process has to do
// the spawning. That something is thirty lines of JavaScript per harness,
// embedded in the binary and written out by `steer init --agent <name>`.
//
// Embedded rather than published, because the binary that writes the shim is
// the binary the shim spawns: there is no version to skew and nothing to
// install.
//
// A shim moves bytes and translates three outcomes; it never parses a command
// line or maps a tool name, which keeps all of that on the Rust side.

use crate::Agent;

pub struct Shim {
    pub agent: Agent,
    /// Relative to the project, which is where all three harnesses look before
    /// the home directory. pi's is `.ts` because its discovery globs only
    /// `*.ts`, and the contents are JavaScript either way.
    pub path: &'static str,
    pub contents: &'static str,
}

/// The files live beside this one rather than inside it, so `node --check` runs
/// on the bytes that ship.
const ALL: &[Shim] = &[
    Shim {
        agent: Agent::Opencode,
        path: ".opencode/plugins/steer.js",
        contents: include_str!("shims/opencode.js"),
    },
    Shim {
        agent: Agent::Pi,
        path: ".pi/extensions/steer.ts",
        contents: include_str!("shims/pi.ts"),
    },
    Shim {
        agent: Agent::Amp,
        path: ".amp/plugins/steer.js",
        contents: include_str!("shims/amp.js"),
    },
];

pub fn of(agent: Agent) -> Option<&'static Shim> {
    ALL.iter().find(|shim| shim.agent == agent)
}

pub fn names() -> String {
    ALL.iter()
        .map(|shim| shim.agent.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

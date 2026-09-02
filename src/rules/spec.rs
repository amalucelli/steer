// The rule language as a config file writes it.
//
// These types are the contract with the TOML on disk: `serde` reads them
// directly, `deny_unknown_fields` turns a typo into a `validate` problem rather
// than a silently inert rule, and the emitter writes them back out. Nothing here
// decides anything — a spec is what a rule says about itself, and the engine
// compiles it before asking it a question.

use crate::Agent;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Exact `tool_name` gate. Absent means the rule sees every tool.
    #[serde(default)]
    pub tool: Option<String>,
    /// Harnesses this rule is valid for. Absent means every one.
    #[serde(default)]
    pub agents: Option<Vec<Agent>>,
    #[serde(rename = "match", default)]
    pub blocks: Vec<MatchBlock>,
    pub action: Action,
    #[serde(default)]
    pub test: TestSpec,
}

/// What a rule claims about itself, checked by `validate` and read by nothing
/// else.
///
/// It sits in its own section because it is the only part of a rule with no
/// effect on a tool call.
///
/// `ignores` says this rule does not match the command, not that steer allows
/// it — another rule still might.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestSpec {
    #[serde(default)]
    pub fires: Vec<String>,
    #[serde(default)]
    pub ignores: Vec<String>,
    /// Commands mapped to what the rewrite must turn them into.
    ///
    /// `fires` only asserts that something happened; a splice that started
    /// cutting the wrong span would keep firing and keep passing.
    #[serde(default)]
    pub rewrites: BTreeMap<String, String>,
}

impl RuleSpec {
    pub fn allows(&self, agent: Agent) -> bool {
        self.agents
            .as_ref()
            .is_none_or(|agents| agents.contains(&agent))
            && self.action.message().covers(agent)
    }

    /// The harnesses this rule can actually reach, from whichever of the two
    /// gates is set. `None` is every one of them.
    pub fn gated_to(&self) -> Option<Vec<Agent>> {
        self.agents
            .clone()
            .or_else(|| self.action.message().named_agents())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatchBlock {
    /// Path to an array; the block holds when some element satisfies it.
    #[serde(default)]
    pub any: Option<String>,
    /// Path to an array; the block holds when every element satisfies it, and
    /// an empty array never satisfies it.
    #[serde(default)]
    pub all: Option<String>,
    #[serde(flatten)]
    pub conditions: BTreeMap<String, Predicate>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    pub any_of: Option<Vec<String>>,
    pub none_of: Option<Vec<String>>,
    pub glob: Option<Vec<String>>,
    pub none_glob: Option<Vec<String>>,
    pub matches: Option<String>,
    pub is: Option<bool>,
}

/// What a rule says when it fires, either once for every harness or once per
/// harness it speaks to.
///
/// A rule's matching is harness-independent — `python3 -` is the same shape
/// under either one — but the tool its message points at is not. With a single
/// message a rule that wants to name `Edit` on Claude Code and `apply_patch` on
/// Codex has to be gated to one of them, which throws away perfectly good
/// matching to avoid shipping an unfollowable sentence.
///
/// Naming a harness is therefore also the gate. A rule with nothing to say to a
/// harness has nothing followable to refuse it with, so it does not apply there.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Message {
    Every(String),
    PerAgent(BTreeMap<Agent, String>),
}

impl Default for Message {
    fn default() -> Message {
        Message::Every(String::new())
    }
}

impl Message {
    /// `None` for the agent asks for every harness's copy at once, which is what
    /// `check` wants: it evaluates rules whatever their gate, so it has no one
    /// harness to speak as.
    pub fn text(&self, agent: Option<Agent>) -> String {
        match (self, agent) {
            (Message::Every(message), _) => message.clone(),
            (Message::PerAgent(per), Some(agent)) => per.get(&agent).cloned().unwrap_or_default(),
            (Message::PerAgent(per), None) => per
                .iter()
                .map(|(agent, message)| format!("{}: {message}", agent.as_str()))
                .collect::<Vec<_>>()
                .join("\n\n"),
        }
    }

    fn covers(&self, agent: Agent) -> bool {
        match self {
            Message::Every(_) => true,
            Message::PerAgent(per) => per.contains_key(&agent),
        }
    }

    fn named_agents(&self) -> Option<Vec<Agent>> {
        match self {
            Message::Every(_) => None,
            Message::PerAgent(per) => Some(per.keys().copied().collect()),
        }
    }

    pub(super) fn is_per_agent(&self) -> bool {
        matches!(self, Message::PerAgent(_))
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Action {
    Deny {
        message: Message,
    },
    Rewrite {
        /// Binary that replaces the matched segment's head. Absent when the
        /// rewrite only edits arguments.
        #[serde(default)]
        replace_head: Option<String>,
        /// Arguments dropped from the matched segment, matched exactly.
        #[serde(default)]
        drop_args: Vec<String>,
        #[serde(default)]
        add_args: Vec<String>,
        #[serde(default)]
        message: Message,
    },
    Context {
        message: Message,
    },
}

impl Action {
    pub fn outcome(&self) -> Outcome {
        match self {
            Action::Deny { .. } => Outcome::Deny,
            Action::Rewrite { .. } => Outcome::Rewrite,
            Action::Context { .. } => Outcome::Context,
        }
    }

    pub fn message(&self) -> &Message {
        match self {
            Action::Deny { message } | Action::Context { message } => message,
            Action::Rewrite { message, .. } => message,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Allow,
    Context,
    Rewrite,
    Deny,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Context => "context",
            Outcome::Rewrite => "rewrite",
            Outcome::Deny => "deny",
        }
    }
}

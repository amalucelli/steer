// The rule language as a config file writes it.
//
// These types are the contract with the TOML on disk: `serde` reads them
// directly, `deny_unknown_fields` turns a typo into a `validate` problem rather
// than a silently inert rule, and the emitter writes them back out. Nothing here
// decides anything — a spec is what a rule says about itself, and the engine
// compiles it before asking it a question.

use crate::harness;
use crate::Agent;
use clap::ValueEnum;
use serde::{Deserialize, Deserializer};
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
    /// Canonical tools the rule's guidance needs the harness to have, from
    /// `harness::TOOLS`. A harness missing any of them does not get the rule.
    ///
    /// The capability gate, as distinct from the `agents` one: "everywhere with
    /// a read tool" is what a rule pointing at a read tool actually means, and
    /// listing the harnesses instead makes every new harness a rule edit.
    #[serde(default)]
    pub requires: Vec<String>,
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
    /// Why a harness never sees this rule, or `None` when it does.
    ///
    /// A harness with nowhere to put a note has no weaker form of one to fall
    /// back to, so a context rule drops for it instead of degrading.
    pub fn dropped_for(&self, agent: Agent) -> Option<String> {
        if self
            .agents
            .as_ref()
            .is_some_and(|agents| !agents.contains(&agent))
        {
            return Some("not in `agents`".into());
        }
        let harness = harness::of(agent);
        if let Some(tool) = self
            .requires
            .iter()
            .find(|tool| harness.vocabulary.name(tool).is_none())
        {
            return Some(format!("no {tool} tool"));
        }
        if !self.action.message().covers(agent) {
            return Some("the message says nothing to it".into());
        }
        if matches!(self.action, Action::Context { .. })
            && harness.capabilities.context == harness::ContextAt::None
        {
            return Some("it takes no context before a call".into());
        }
        None
    }

    /// The first name in this rule that no payload can carry, because ingest
    /// renames it before matching: the name as written and the canonical name
    /// it was meant to be. Both halves of a rule can be dead this way — a gate
    /// on a tool, and a condition on a field inside the tool input.
    ///
    /// Positive matchers only: a `none_of` on a dead name widens the rule
    /// rather than killing it.
    pub fn dead_gate(&self) -> Option<(&str, &'static str)> {
        let tools = self.tool.iter().chain(
            self.blocks
                .iter()
                .filter_map(|block| block.conditions.get("tool_name"))
                .filter_map(|predicate| predicate.any_of.as_ref())
                .flatten(),
        );
        let fields = self
            .blocks
            .iter()
            .flat_map(|block| &block.conditions)
            .filter(|(_, predicate)| predicate.asserts())
            .map(|(field, _)| field);
        tools
            .filter_map(|name| Some((name.as_str(), harness::rewritten(name)?)))
            .chain(
                fields.filter_map(|field| Some((field.as_str(), harness::renamed_field(field)?))),
            )
            .next()
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

impl Predicate {
    /// Whether the condition claims something about the value rather than about
    /// its absence, which is what makes a dead field name fatal: a `none_of`
    /// against a field nothing carries excludes nothing and the rule still
    /// fires.
    pub(crate) fn asserts(&self) -> bool {
        self.any_of.is_some() || self.glob.is_some() || self.matches.is_some() || self.is.is_some()
    }
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
///
/// A `default` key opts out of that gate: it covers every harness, a key naming
/// one overrides it there, and the tool tokens keep it followable everywhere.
/// Without a `default` a rule reaches exactly the harnesses its table names, so
/// whatever harness ships next is outside it until someone adds a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Every(String),
    PerAgent(BTreeMap<Audience, String>),
}

/// Read in two steps rather than as an untagged enum over `Audience`, which
/// reports a mistyped harness key as "no variant matched" against the whole
/// action. A key is the gate, so a typo in one silently narrows the rule to the
/// harnesses that are left.
impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Message, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Every(String),
            PerAgent(BTreeMap<String, String>),
        }
        let per = match Raw::deserialize(deserializer)? {
            Raw::Every(text) => return Ok(Message::Every(text)),
            Raw::PerAgent(per) => per,
        };
        per.into_iter()
            .map(|(key, text)| match Audience::parse(&key) {
                Some(audience) => Ok((audience, text)),
                None => Err(serde::de::Error::custom(format!(
                    "`{key}` is not a harness; the keys of a message table are default|{}",
                    harness::names()
                ))),
            })
            .collect::<Result<_, _>>()
            .map(Message::PerAgent)
    }
}

/// `Default` sorts first, so a table written back out leads with the copy the
/// named keys are exceptions to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Audience {
    Default,
    Harness(Agent),
}

impl Audience {
    pub fn as_str(&self) -> &'static str {
        match self {
            Audience::Default => "default",
            Audience::Harness(agent) => agent.as_str(),
        }
    }

    /// Against `Agent` itself, so the keys a message may carry and the harnesses
    /// steer speaks to stay one list rather than two that can drift.
    fn parse(key: &str) -> Option<Audience> {
        if key == "default" {
            return Some(Audience::Default);
        }
        Agent::value_variants()
            .iter()
            .copied()
            .find(|agent| agent.as_str() == key)
            .map(Audience::Harness)
    }
}

impl Default for Message {
    fn default() -> Message {
        Message::Every(String::new())
    }
}

impl Message {
    /// `None` for the agent asks for every harness's copy at once, which is what
    /// `check` wants: it evaluates rules whatever their gate, so it has no one
    /// harness to speak as — and no vocabulary to render a tool token through
    /// either, so those stay as the rule wrote them.
    pub fn text(&self, agent: Option<Agent>) -> String {
        let text = match (self, agent) {
            (Message::Every(message), _) => message.clone(),
            (Message::PerAgent(per), Some(agent)) => per
                .get(&Audience::Harness(agent))
                .or_else(|| per.get(&Audience::Default))
                .cloned()
                .unwrap_or_default(),
            (Message::PerAgent(per), None) => per
                .iter()
                .map(|(audience, message)| format!("{}: {message}", audience.as_str()))
                .collect::<Vec<_>>()
                .join("\n\n"),
        };
        match agent {
            Some(agent) => harness::of(agent).vocabulary.fill(&text),
            None => text,
        }
    }

    fn covers(&self, agent: Agent) -> bool {
        match self {
            Message::Every(_) => true,
            Message::PerAgent(per) => {
                per.contains_key(&Audience::Default) || per.contains_key(&Audience::Harness(agent))
            }
        }
    }

    /// Every copy this message holds, before a vocabulary fills its tokens in.
    /// A token is checked against what the rule requires, which is a question
    /// about the text as written.
    pub(super) fn texts(&self) -> Vec<&str> {
        match self {
            Message::Every(text) => vec![text.as_str()],
            Message::PerAgent(per) => per.values().map(String::as_str).collect(),
        }
    }

    /// A `default` covers every harness, which leaves the keys beside it as
    /// copy rather than as the rule's gate.
    pub(super) fn gates(&self) -> bool {
        matches!(self, Message::PerAgent(per) if !per.contains_key(&Audience::Default))
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

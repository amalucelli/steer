// The harnesses steer speaks to, one descriptor each.
//
// steer cannot be run against a live install of any of them: every descriptor is
// built from that harness's published documentation, so a wrong guess is the
// expected case. The table is shaped so correcting one costs a field rather than
// a hunt through ingest and rendering.
//
// Which harness sent a payload is never inferred from its shape: the hook is
// registered with `--agent`, and a payload arriving without one is allowed
// through with a note asking for it. Harnesses copy each other's envelopes, so a
// shape that looks like Claude Code's is not evidence it is one.
//
// The response format is an enum rather than a function per harness because
// harnesses copy each other's envelopes.
//
// Adding a harness, in order:
//
//  1. Add a variant to `Agent` in `main.rs`, with its name in `Agent::as_str`.
//  2. Add a `static` below and an arm to `of`, which matches every agent
//     exhaustively, so a missing descriptor is a compile error rather than a
//     harness that silently behaves like Claude Code.
//  3. Fill `ingest` and `capabilities`. The field docs on `Ingest` say what
//     each pointer and flag is for. `path` stays empty unless the harness
//     publishes the field name, where a guess is a rule that silently matches
//     nothing.
//  4. Fill `vocabulary`. A wrong name here is a deny pointing at a tool that
//     does not exist, and `None` is the answer for a tool the harness has no
//     name for — never the shell tool standing in for it.
//  5. Name an existing `Response`. Write a new variant only when no envelope
//     already fits.
//  6. Add a row to the fixture table in `tests/rules/harness.rs`, built from the
//     payload the harness's own documentation publishes.
//  7. Only if the harness loads a module instead of spawning a process: name
//     `Response::Neutral`, and add the plugin file and its destination to the
//     table in `shim.rs`. The payload is then the shim's own, so step 3 reads
//     off the shim rather than off the harness's documentation.

use crate::rules::{Decision, Outcome};
use crate::{Agent, Event};
use clap::ValueEnum;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

pub struct Harness {
    pub agent: Agent,
    pub ingest: Ingest,
    pub capabilities: Capabilities,
    pub vocabulary: Vocabulary,
    pub response: Response,
}

/// Where the payload keeps what the rules read, and what this harness calls the
/// tools they gate on.
pub struct Ingest {
    /// The harness's tool names against the canonical vocabulary. A name absent
    /// from the table reaches the rules unchanged, which is what keeps
    /// `NotebookEdit` and MCP tools addressable.
    pub tools: &'static [(&'static str, &'static str)],
    /// JSON pointer to the name of the tool being called. A pointer rather than
    /// a key because Antigravity CLI keeps it beside the arguments under
    /// `toolCall`.
    pub name: &'static str,
    pub input: &'static str,
    /// JSON pointer to the working directory of the session, which is what a
    /// rule reading `in_workspace` weighs against and where config discovery
    /// starts. Goose calls it `working_dir`, Windsurf keeps it beside the
    /// command, and Antigravity sends a list of workspace roots the pointer
    /// indexes into.
    pub cwd: &'static str,
    /// Set where that key holds a string of JSON rather than an object. GitHub
    /// Copilot CLI documents `toolArgs` as an object and ships it as a string;
    /// reading the documented shape finds no command and lets every rule pass.
    pub encoded: bool,
    /// Field inside the tool input carrying the shell command line, renamed to
    /// `command` before the rules see it and written back here for a rewrite.
    pub command: &'static str,
    /// Fields inside the tool input carrying the file a file tool acts on, any
    /// of which is renamed to `path`. Several because one harness's tools need
    /// not agree with each other: Claude Code's file tools say `file_path` and
    /// its notebook tool says `notebook_path`. The first one the payload
    /// carries wins.
    ///
    /// Empty where the harness publishes no file-tool input schema. Left
    /// unmapped rather than guessed: a payload that already spells it `path`
    /// then works by accident, where a wrong name here is a rule that matches
    /// nothing and says so nowhere.
    pub path: &'static [&'static str],
    /// Object the command field sits inside, where a harness nests it one level
    /// down. Antigravity CLI keeps it at `args.CommandLine`, PascalCase inside
    /// a camelCase envelope.
    pub command_in: Option<&'static str>,
}

pub struct Capabilities {
    /// Whether the harness accepts an edited tool input. Without it a rewrite
    /// degrades to a deny carrying the replacement command, which reaches the
    /// model as guidance rather than as an edit.
    pub rewrite: bool,
    pub context: ContextAt,
}

/// Where a harness will take a note steer injects. Pre-execution or nowhere:
/// there is no post-execution route, because a `context` rule that arrives
/// after the call has already answered a question nobody asked yet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContextAt {
    Pre,
    None,
}

/// What this harness's model can call, for the messages that have to name a
/// tool. The canonical vocabulary is for gates and never for prose: "use the
/// edit tool" is not a call anything can make, so a message writes `{edit}` and
/// renders it here.
///
/// Everything but the shell is optional, because a harness that has no read
/// tool has no name to point a read at. Filling one in with the shell tool is
/// the failure this exists to stop: a rule denying a shell command would
/// recommend a shell command, and nothing would catch it. `requires` on a rule
/// is the other half — a rule naming a tool no longer reaches a harness that
/// lacks it.
pub struct Vocabulary {
    pub shell: &'static str,
    pub read: Option<&'static str>,
    pub edit: Option<&'static str>,
    pub write: Option<&'static str>,
    pub search: Option<&'static str>,
}

/// The tools a message may write as a `{token}` and a rule may list in
/// `requires`. `shell` is here because a message renders it; requiring it says
/// nothing, since every harness has one.
pub const TOOLS: [&str; 5] = ["shell", "read", "edit", "write", "search"];

impl Vocabulary {
    /// What this harness calls a canonical tool. `None` both for a tool it does
    /// not have and for a name that is not a tool at all — the two are told
    /// apart against `TOOLS`, which is where a typo is caught.
    pub fn name(&self, tool: &str) -> Option<&'static str> {
        match tool {
            "shell" => Some(self.shell),
            "read" => self.read,
            "edit" => self.edit,
            "write" => self.write,
            "search" => self.search,
            _ => None,
        }
    }

    /// A message with each token replaced by this harness's own name for that
    /// tool. Deliberately not a template language: anything else in braces is
    /// left as the rule wrote it.
    ///
    /// A token for a tool this harness lacks is left standing too, and no rule
    /// that compiled can produce one: a message naming a tool has to require
    /// it, and requiring it drops the rule here.
    pub fn fill(&self, message: &str) -> String {
        TOOLS
            .iter()
            .fold(message.to_string(), |text, tool| match self.name(tool) {
                Some(name) => text.replace(&format!("{{{tool}}}"), name),
                None => text,
            })
    }
}

/// The wire shape a harness reads a decision as.
pub enum Response {
    /// Claude Code's nested `hookSpecificOutput` envelope. `additionalContext`
    /// and `systemMessage` sit inside it on purpose; at the top level Claude
    /// Code drops them silently.
    Claude,
    /// Junie's flat object: `decision`, `reason`, `updatedInput` and
    /// `additionalContext` at the top level with no wrapper.
    Junie,
    /// Gemini CLI's flat `decision` and `reason`, with an edited tool input
    /// nested under `hookSpecificOutput.tool_input`.
    Gemini,
    /// Cursor's flat `permission`, with a message to the user and a message to
    /// the model as separate fields — the split that stops Cursor from reusing
    /// Claude Code's envelope.
    Cursor,
    /// GitHub Copilot CLI's flat `permissionDecision`, `permissionDecisionReason`
    /// and `modifiedArgs`. Claude Code's field names with no envelope around
    /// them.
    Copilot,
    /// Crush's flat object, versioned: `version`, `decision`, `reason`,
    /// `context` and `updated_input`.
    Crush,
    /// Cline's `cancel` flag with the reason beside it, plus a note it prepends
    /// to the model's context.
    Cline,
    /// Windsurf answers on the exit code, with the reason on stderr and no
    /// decision document at all. The only format here that says nothing on
    /// stdout.
    Windsurf,
    /// steer's own shape, for the harnesses reached through an embedded shim.
    /// steer owns both ends of this one, so it is shaped for the shim rather
    /// than copied from a harness — an outcome and a string is everything
    /// thirty lines of JavaScript can act on without learning what a rule is.
    Neutral,
}

const CLAUDE_TOOLS: &[(&str, &str)] = &[
    ("Bash", "shell"),
    ("Read", "read"),
    ("Edit", "edit"),
    ("Write", "write"),
    ("Grep", "search"),
    ("Glob", "find"),
    ("WebFetch", "fetch"),
];

/// Codex ships `shell` and `apply_patch`. That payloads have also been seen
/// carrying Claude Code's names is inherited from the hook this replaced rather
/// than stated anywhere, so both spellings map and the assumption stays visible.
const CODEX_TOOLS: &[(&str, &str)] = &[
    ("shell", "shell"),
    ("Bash", "shell"),
    ("apply_patch", "edit"),
    ("Read", "read"),
    ("Edit", "edit"),
    ("Write", "write"),
    ("Grep", "search"),
    ("Glob", "find"),
    ("WebFetch", "fetch"),
];

/// Gemini CLI's own tool names, which Qwen Code inherits by deriving from it.
/// Only `run_shell_command` is confirmed in Qwen's own documentation; the rest
/// are Gemini's, assumed unchanged across the fork.
///
/// `list_directory` maps to `find` because the canonical vocabulary has no
/// listing tool and locating files is what both are for.
const GEMINI_TOOLS: &[(&str, &str)] = &[
    ("run_shell_command", "shell"),
    ("read_file", "read"),
    ("write_file", "write"),
    ("replace", "edit"),
    ("search_file_content", "search"),
    ("glob", "find"),
    ("list_directory", "find"),
];

/// Claude Code's names minus `WebFetch`, which Junie's tool list does not
/// carry.
const JUNIE_TOOLS: &[(&str, &str)] = &[
    ("Bash", "shell"),
    ("Read", "read"),
    ("Edit", "edit"),
    ("Write", "write"),
    ("Grep", "search"),
    ("Glob", "find"),
];

/// `List` maps to `find`, a judgement about the canonical vocabulary rather
/// than anything Continue.dev states.
const CONTINUE_TOOLS: &[(&str, &str)] = &[
    ("Bash", "shell"),
    ("Read", "read"),
    ("Edit", "edit"),
    ("Write", "write"),
    ("Search", "search"),
    ("List", "find"),
];

/// Cursor has no edit tool: an edit and a create both arrive as `Write`, so a
/// rule that tells changing a file from making one cannot tell them apart here.
/// That is the lossy half of normalization, and it is Cursor's tool list rather
/// than a choice steer made.
const CURSOR_TOOLS: &[(&str, &str)] = &[
    ("Shell", "shell"),
    ("Read", "read"),
    ("Write", "edit"),
    ("Grep", "search"),
];

/// `powershell` is the same tool on Windows, so both land on `shell` and a rule
/// written once covers either.
const COPILOT_TOOLS: &[(&str, &str)] = &[
    ("bash", "shell"),
    ("powershell", "shell"),
    ("view", "read"),
    ("edit", "edit"),
    ("create", "write"),
    ("grep", "search"),
    ("glob", "find"),
    ("web_fetch", "fetch"),
];

const CRUSH_TOOLS: &[(&str, &str)] = &[
    ("bash", "shell"),
    ("view", "read"),
    ("edit", "edit"),
    ("write", "write"),
    ("grep", "search"),
    ("glob", "find"),
    ("ls", "find"),
];

const CLINE_TOOLS: &[(&str, &str)] = &[
    ("execute_command", "shell"),
    ("read_file", "read"),
    ("write_to_file", "write"),
    ("replace_in_file", "edit"),
    ("search_files", "search"),
    ("list_files", "find"),
];

/// Goose's reference page names the shell and the editor and stops there, so
/// this table stops there too. A read or a search arrives under whatever Goose
/// calls it and reaches the rules unmapped, which is a gate that does not fire
/// rather than one that fires on the wrong call.
const GOOSE_TOOLS: &[(&str, &str)] = &[
    ("developer__shell", "shell"),
    ("developer__text_editor", "edit"),
];

/// Windsurf registers a hook per action rather than per tool, so the action is
/// the tool identity — there is no tool-name field to map. `pre_write_code`
/// covers editing and creating alike.
const WINDSURF_TOOLS: &[(&str, &str)] = &[
    ("pre_run_command", "shell"),
    ("pre_read_code", "read"),
    ("pre_write_code", "edit"),
];

/// Only `run_command` is on an official page. The rest are third-party reports
/// of Antigravity's tool list, so a rule gating on one of them may be gating on
/// a name that does not exist.
const ANTIGRAVITY_TOOLS: &[(&str, &str)] = &[
    ("run_command", "shell"),
    ("view_file", "read"),
    ("replace_file_content", "edit"),
    ("write_to_file", "write"),
    ("grep_search", "search"),
    ("list_dir", "find"),
];

const OPENCODE_TOOLS: &[(&str, &str)] = &[
    ("bash", "shell"),
    ("read", "read"),
    ("edit", "edit"),
    ("write", "write"),
    ("grep", "search"),
    ("glob", "find"),
];

const PI_TOOLS: &[(&str, &str)] = &[
    ("bash", "shell"),
    ("powershell", "shell"),
    ("read", "read"),
    ("edit", "edit"),
    ("write", "write"),
    ("grep", "search"),
    ("find", "find"),
    ("ls", "find"),
];

/// The only harness mixing cases in one list: `Bash`, `Read` and `Grep` are
/// Claude Code's spellings, `edit_file` and `create_file` are Amp's own.
///
/// Amp's deep mode runs the same shell under a second name, `shell_command`,
/// and that one keeps its command in `command` rather than `cmd`. One field
/// name per descriptor, so mapping it here would find no command and evaluate
/// an empty one; it is left unmapped, which means shell rules do not fire in
/// deep mode.
const AMP_TOOLS: &[(&str, &str)] = &[
    ("Bash", "shell"),
    ("Read", "read"),
    ("edit_file", "edit"),
    ("create_file", "write"),
    ("Grep", "search"),
    ("glob", "find"),
];

static CLAUDE: Harness = Harness {
    agent: Agent::Claude,
    ingest: Ingest {
        tools: CLAUDE_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        // `NotebookEdit` is the one Claude Code tool that spells it otherwise,
        // and it is left mapped here rather than on the harnesses that copy
        // Claude's envelope, none of which documents a notebook tool.
        path: &["file_path", "notebook_path"],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "Bash",
        read: Some("Read"),
        edit: Some("Edit"),
        write: Some("Write"),
        search: Some("Grep"),
    },
    response: Response::Claude,
};

static CODEX: Harness = Harness {
    agent: Agent::Codex,
    ingest: Ingest {
        tools: CODEX_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        // `apply_patch` carries a patch rather than a path, so there is no
        // field to rename.
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        // Codex accepts `updatedInput` only together with an approval, and its
        // `ask` decision is unimplemented, so there is no way to edit the call
        // and still route it through the user.
        rewrite: false,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "shell",
        // Codex's published tool list has no read and no search.
        read: None,
        search: None,
        // `apply_patch` takes a whole-file addition as well as a diff, so it is
        // the create tool too.
        edit: Some("apply_patch"),
        write: Some("apply_patch"),
    },
    response: Response::Claude,
};

static QWEN: Harness = Harness {
    agent: Agent::Qwen,
    ingest: Ingest {
        tools: GEMINI_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "run_shell_command",
        read: Some("read_file"),
        edit: Some("replace"),
        write: Some("write_file"),
        search: Some("search_file_content"),
    },
    response: Response::Claude,
};

/// Continue.dev reads `~/.claude/settings.json` and `.claude/settings.json`
/// itself, so a hand-written Claude Code registration fires under it with
/// `--agent claude`. Harmless while the two contracts match, and the reason
/// this descriptor exists is the day they stop.
static CONTINUE: Harness = Harness {
    agent: Agent::Continue,
    ingest: Ingest {
        tools: CONTINUE_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "Bash",
        read: Some("Read"),
        edit: Some("Edit"),
        write: Some("Write"),
        search: Some("Search"),
    },
    response: Response::Claude,
};

/// Junie reads the same request Claude Code sends and answers with a flat
/// object rather than an envelope. Exit code 2 blocks as well, but steer keeps
/// exiting 0 and saying it in the JSON, which is the path that also carries a
/// reason.
static JUNIE: Harness = Harness {
    agent: Agent::Junie,
    ingest: Ingest {
        tools: JUNIE_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "Bash",
        read: Some("Read"),
        edit: Some("Edit"),
        write: Some("Write"),
        search: Some("Grep"),
    },
    response: Response::Junie,
};

/// Gemini CLI fires `BeforeTool` where the others fire `PreToolUse`, which
/// changes nothing steer emits: its response carries no event name, and the
/// event steer is told about arrives on `--event` rather than from the payload.
///
/// Its own `docs/hooks/reference.md` settles both capabilities. Rewrite is
/// there — `hookSpecificOutput.tool_input`: "An object that merges with and
/// overrides the model's arguments before execution". Context is not: the
/// output fields `BeforeTool` names are `decision`, `reason`,
/// `hookSpecificOutput.tool_input` and `continue`, and `additionalContext`
/// appears only under `AfterTool` and the prompt events.
///
/// Exit code 2 blocks with stderr as the reason. steer stays on exit 0, which
/// the same doc calls "preferred for all logic".
static GEMINI: Harness = Harness {
    agent: Agent::Gemini,
    ingest: Ingest {
        tools: GEMINI_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "run_shell_command",
        read: Some("read_file"),
        edit: Some("replace"),
        write: Some("write_file"),
        search: Some("search_file_content"),
    },
    response: Response::Gemini,
};

/// Registered natively in `.cursor/hooks.json` rather than through
/// `~/.claude/settings.json`, which Cursor also reads. The reason is the one
/// field its compatibility table cannot map: Claude Code's
/// `permissionDecisionReason` lands on `user_message`, which Cursor shows the
/// human, and nothing on the Claude side maps onto `agent_message`, which is
/// what the model reads. A deny sent as Claude's envelope would therefore be
/// invisible to the thing it is arguing with.
static CURSOR: Harness = Harness {
    agent: Agent::Cursor,
    ingest: Ingest {
        tools: CURSOR_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        // `additional_context` is a postToolUse field on Cursor, and steer has
        // no post-execution route for a note.
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "Shell",
        read: Some("Read"),
        edit: Some("Write"),
        write: Some("Write"),
        search: Some("Grep"),
    },
    response: Response::Cursor,
};

/// `toolArgs` is documented as an object and ships as a string of JSON. steer
/// decodes it on the way in and hands `modifiedArgs` back as an object, which is
/// what the documentation asks for; if the runtime wants the string back, that
/// is the other half of the same bug.
static COPILOT: Harness = Harness {
    agent: Agent::Copilot,
    ingest: Ingest {
        tools: COPILOT_TOOLS,
        name: "/toolName",
        input: "/toolArgs",
        cwd: "/cwd",
        encoded: true,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        // `modifiedArgs` replaces the arguments outright rather than merging.
        // Harmless here: steer hands back the object the harness sent with the
        // command edited, so nothing it did not know about can be dropped.
        rewrite: true,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "bash",
        read: Some("view"),
        edit: Some("edit"),
        write: Some("create"),
        search: Some("grep"),
    },
    response: Response::Copilot,
};

/// Crush's `updated_input` is a merge patch into the input it already has,
/// where Junie's and Copilot's replace it. steer sends the whole input either
/// way — a rewrite only ever edits the command field of the object the harness
/// sent, never removes one — so the two semantics land on the same call and the
/// descriptor needs nothing to tell them apart.
///
/// Its exit code 49 halts the turn outright, which is stronger than a deny and
/// has no rule steer can express, so steer keeps exiting 0.
static CRUSH: Harness = Harness {
    agent: Agent::Crush,
    ingest: Ingest {
        tools: CRUSH_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "bash",
        read: Some("view"),
        edit: Some("edit"),
        write: Some("write"),
        search: Some("grep"),
    },
    response: Response::Crush,
};

/// Registered as an executable at `.clinerules/hooks/PreToolUse`, and the only
/// harness naming the tool `tool` and its arguments `parameters`.
static CLINE: Harness = Harness {
    agent: Agent::Cline,
    ingest: Ingest {
        tools: CLINE_TOOLS,
        name: "/tool",
        input: "/parameters",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &["path"],
        command_in: None,
    },
    capabilities: Capabilities {
        // Cline's response has no input field of any kind, so a rewrite has
        // nowhere to land and degrades to a deny carrying the command.
        rewrite: false,
        context: ContextAt::Pre,
    },
    vocabulary: Vocabulary {
        shell: "execute_command",
        read: Some("read_file"),
        edit: Some("replace_in_file"),
        write: Some("write_to_file"),
        search: Some("search_files"),
    },
    response: Response::Cline,
};

/// Goose's own documentation disagrees with itself: a blog post describes
/// capabilities its hooks reference page does not carry. This descriptor follows
/// the reference page, which gives `PreToolUse` a `decision` of `block` or
/// `allow` with a `reason` and nothing else.
///
/// That response is Junie's deny shape exactly, so it reuses the variant. What
/// does not carry over is where a note goes: Junie's `additionalContext` is a
/// key Goose does not document, so steer's own breakage note reaches Goose's
/// model or nowhere.
static GOOSE: Harness = Harness {
    agent: Agent::Goose,
    ingest: Ingest {
        tools: GOOSE_TOOLS,
        name: "/tool_name",
        input: "/tool_input",
        cwd: "/working_dir",
        encoded: false,
        command: "command",
        path: &[],
        command_in: None,
    },
    capabilities: Capabilities {
        // Not documented either way, and the sources that disagree about Goose
        // disagree here too. Absent is the safe reading: a rewrite degrades to
        // a deny the model can act on rather than to an edit Goose ignores.
        rewrite: false,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "developer__shell",
        // Goose's reference page enumerates neither, and absence is all there
        // is to infer from.
        read: None,
        search: None,
        edit: Some("developer__text_editor"),
        write: Some("developer__text_editor"),
    },
    response: Response::Junie,
};

/// The most divergent request in the set: no tool name, no tool input object,
/// and the command beside the working directory under `tool_info`.
static WINDSURF: Harness = Harness {
    agent: Agent::Windsurf,
    ingest: Ingest {
        tools: WINDSURF_TOOLS,
        name: "/agent_action_name",
        input: "/tool_info",
        cwd: "/tool_info/cwd",
        encoded: false,
        command: "command_line",
        path: &["file_path"],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: false,
        context: ContextAt::None,
    },
    // The least verified field in this file. Windsurf documents the action
    // names it fires hooks on, never the names Cascade calls its own tools by,
    // so these are third-party reports and a deny naming one may name nothing.
    vocabulary: Vocabulary {
        shell: "run_command",
        read: Some("view_file"),
        edit: Some("replace_file_content"),
        write: Some("write_to_file"),
        search: Some("grep_search"),
    },
    response: Response::Windsurf,
};

/// Google's forward path, binary `agy`, registered in `.agents/hooks.json` or
/// `~/.gemini/config/hooks.json`. The command sits at `toolCall.args.CommandLine`
/// — PascalCase inside a camelCase envelope — which is the shape `command_in`
/// exists for, and the workspace arrives as a list of roots rather than one
/// directory.
///
/// Its decision enum is the widest here: `allow`, `deny`, `ask`, `force_ask` and
/// `deny_unless_prior_grant`, plus `permissionOverrides`. steer says `allow` and
/// `deny`, which makes the response Gemini CLI's flat pair exactly, so it reuses
/// that variant. A note rides on `systemMessage` there, which Antigravity does
/// not document.
static ANTIGRAVITY: Harness = Harness {
    agent: Agent::Antigravity,
    ingest: Ingest {
        tools: ANTIGRAVITY_TOOLS,
        name: "/toolCall/name",
        input: "/toolCall",
        cwd: "/workspacePaths/0",
        encoded: false,
        command: "CommandLine",
        path: &[],
        command_in: Some("args"),
    },
    capabilities: Capabilities {
        // No input-rewrite field is documented on any of the five decisions.
        rewrite: false,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "run_command",
        read: Some("view_file"),
        edit: Some("replace_file_content"),
        write: Some("write_to_file"),
        search: Some("grep_search"),
    },
    response: Response::Gemini,
};

/// The first of three harnesses steer cannot be registered into: OpenCode loads
/// a JavaScript module into its own process and calls it, so there is no command
/// for a config file to name. `steer init --agent opencode` writes a shim that
/// does the spawning, and the payload below is the shim's, not OpenCode's — the
/// shim forwards the harness's own tool name and arguments rather than
/// translating them, which is what keeps the mapping in one language.
static OPENCODE: Harness = Harness {
    agent: Agent::Opencode,
    ingest: Ingest {
        tools: OPENCODE_TOOLS,
        name: "/tool",
        input: "/args",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &["filePath"],
        command_in: None,
    },
    capabilities: Capabilities {
        // The shim assigns into the arguments object OpenCode passes on to the
        // tool, so an edited command runs.
        rewrite: true,
        // `tool.execute.before` has no field for a note, and the after-hook
        // that could carry one runs too late to be a `context` rule.
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "bash",
        read: Some("read"),
        edit: Some("edit"),
        write: Some("write"),
        search: Some("grep"),
    },
    response: Response::Neutral,
};

/// pi is the one shim that cannot pipe: its subprocess API takes no stdin, so
/// the shim pipes through `sh` and strips the content-bearing fields on the way
/// to keep the payload inside `ARG_MAX`. Nothing steer reads is lost — rules
/// gate on `path`, never on a file's contents.
static PI: Harness = Harness {
    agent: Agent::Pi,
    ingest: Ingest {
        tools: PI_TOOLS,
        name: "/toolName",
        input: "/input",
        cwd: "/cwd",
        encoded: false,
        command: "command",
        path: &["path"],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "bash",
        read: Some("read"),
        edit: Some("edit"),
        write: Some("write"),
        search: Some("grep"),
    },
    response: Response::Neutral,
};

/// Reached through its plugin API rather than the permission `delegate` path.
/// Delegate is a smaller change and a worse one: it carries no tool name, has no
/// rewrite, and denies by exiting non-zero, which is the one thing the hook path
/// may never do.
static AMP: Harness = Harness {
    agent: Agent::Amp,
    ingest: Ingest {
        tools: AMP_TOOLS,
        name: "/tool",
        input: "/input",
        cwd: "/cwd",
        encoded: false,
        command: "cmd",
        path: &["path"],
        command_in: None,
    },
    capabilities: Capabilities {
        rewrite: true,
        context: ContextAt::None,
    },
    vocabulary: Vocabulary {
        shell: "Bash",
        read: Some("Read"),
        edit: Some("edit_file"),
        write: Some("create_file"),
        search: Some("Grep"),
    },
    response: Response::Neutral,
};

/// Every descriptor, in the order `Agent` declares its variants. Derived from
/// that enum rather than listed separately, so a harness cannot be reachable
/// through `of` while missing from everything that walks the table.
pub fn all() -> impl Iterator<Item = &'static Harness> {
    Agent::value_variants().iter().copied().map(of)
}

pub fn of(agent: Agent) -> &'static Harness {
    match agent {
        Agent::Claude => &CLAUDE,
        Agent::Codex => &CODEX,
        Agent::Qwen => &QWEN,
        Agent::Continue => &CONTINUE,
        Agent::Junie => &JUNIE,
        Agent::Gemini => &GEMINI,
        Agent::Cursor => &CURSOR,
        Agent::Copilot => &COPILOT,
        Agent::Crush => &CRUSH,
        Agent::Cline => &CLINE,
        Agent::Goose => &GOOSE,
        Agent::Windsurf => &WINDSURF,
        Agent::Antigravity => &ANTIGRAVITY,
        Agent::Opencode => &OPENCODE,
        Agent::Pi => &PI,
        Agent::Amp => &AMP,
    }
}

/// The canonical name ingest would have turned `name` into before any rule saw
/// it, which is what makes a gate on `name` unmatchable. `None` where every
/// harness leaves the name alone — identity mappings included, so `tool =
/// "write"` stays a gate that fires.
///
/// Derived from the descriptors rather than listed: a harness contributing
/// `Shell` or `view` retires those spellings as gates by arriving.
pub fn rewritten(name: &str) -> Option<&'static str> {
    all().find_map(|harness| harness.ingest.canonical(name).filter(|to| *to != name))
}

/// The same question one level down, for the fields inside a tool input that
/// ingest renames: `file_path` and `notebook_path` can never match because they
/// arrive at the rules as `path`, and `cmd` because it arrives as `command`.
///
/// Only the fields some descriptor maps, so `head`, `args`, `parsed.segments`
/// and the rest of steer's own vocabulary stay legal — and so does any field no
/// harness renames, which is what keeps an undocumented payload addressable.
pub fn renamed_field(name: &str) -> Option<&'static str> {
    all()
        .flat_map(|harness| {
            std::iter::once((harness.ingest.command, "command"))
                .chain(harness.ingest.path.iter().map(|field| (*field, "path")))
        })
        .find_map(|(field, to)| (field == name && field != to).then_some(to))
}

pub fn names() -> String {
    all()
        .map(|harness| harness.agent.as_str())
        .collect::<Vec<_>>()
        .join("|")
}

impl Ingest {
    pub fn canonical(&self, tool_name: &str) -> Option<&'static str> {
        self.tools
            .iter()
            .find(|(harness_name, _)| *harness_name == tool_name)
            .map(|(_, canonical)| *canonical)
    }

    /// The tool input as the rules read it, with the harness's command field
    /// renamed to `command` and its file field to `path`. One document shape for
    /// every harness is what keeps the rule language from growing a per-harness
    /// dialect.
    pub fn normalize(&self, mut tool_input: Value) -> Value {
        let lifted = self
            .slot(&mut tool_input)
            .and_then(|fields| fields.remove(self.command));
        if let (Some(command), Some(fields)) = (lifted, tool_input.as_object_mut()) {
            fields.insert("command".into(), command);
        }
        // No `path_in`: no harness documented so far nests the file it acts on,
        // and a rewrite never edits one, so there is nothing to splice back.
        let named = self
            .path
            .iter()
            .find_map(|field| tool_input.as_object_mut()?.remove(*field));
        if let (Some(path), Some(fields)) = (named, tool_input.as_object_mut()) {
            fields.insert("path".into(), path);
        }
        tool_input
    }

    /// The tool as the payload names it, empty where the payload carries no
    /// name at all — which reaches the rules as a tool no gate matches.
    pub fn tool_name<'a>(&self, payload: &'a Value) -> &'a str {
        payload
            .pointer(self.name)
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The session's working directory. `None` leaves a rule that needs one
    /// declining rather than matching against a directory steer guessed.
    pub fn workspace(&self, payload: &Value) -> Option<PathBuf> {
        payload
            .pointer(self.cwd)
            .and_then(Value::as_str)
            .map(PathBuf::from)
    }

    /// The tool input in the harness's own field names. A payload without one
    /// reads as empty rather than as an error: the rules then match nothing and
    /// the call goes through.
    pub fn read(&self, payload: &mut Value) -> Value {
        let Some(value) = payload
            .pointer_mut(self.input)
            .filter(|value| !value.is_null())
        else {
            return json!({});
        };
        let value = value.take();
        if !self.encoded {
            return value;
        }
        // An object arriving is the doc bug being fixed rather than a payload
        // steer has to refuse.
        value
            .as_str()
            .and_then(|text| serde_json::from_str(text).ok())
            .unwrap_or(value)
    }

    /// Puts a rewritten command back where this harness expects to read it.
    /// False when the input is not the shape the descriptor says it is, which
    /// holds the rewrite back rather than handing over an edit the harness
    /// would apply to a field it does not read.
    fn splice(&self, tool_input: &mut Value, command: &str) -> bool {
        match self.slot(tool_input) {
            Some(fields) => {
                fields.insert(self.command.into(), json!(command));
                true
            }
            None => false,
        }
    }

    fn slot<'a>(&self, tool_input: &'a mut Value) -> Option<&'a mut Map<String, Value>> {
        let fields = tool_input.as_object_mut()?;
        match self.command_in {
            None => Some(fields),
            Some(outer) => fields.get_mut(outer)?.as_object_mut(),
        }
    }
}

/// A decision reduced to what the harness can act on, before any one response
/// format spells it out. The degradations live here so a format is only ever
/// asked to serialize something the harness already supports.
enum Verdict {
    /// Exit 0 with no stdout, which leaves the harness's own permission flow
    /// untouched.
    Silent,
    Deny(String),
    Update {
        input: Value,
        /// The replacement on its own, for the formats that take a command
        /// rather than an input object. Carried rather than read back out of
        /// `input`, where finding it again means knowing the harness's field
        /// name a second time.
        command: String,
        message: String,
    },
    Context(String),
}

/// What steer hands back. Almost every harness reads a decision document on
/// stdout and ignores the exit code, so the other two channels are `None` and 0
/// throughout — except on Windsurf, which has no document at all and answers on
/// the exit code with the reason on stderr.
pub struct Answer {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub code: i32,
}

impl Answer {
    fn stdout(body: Option<String>) -> Answer {
        Answer {
            stdout: body,
            stderr: None,
            code: 0,
        }
    }
}

impl Harness {
    /// `note` is a misconfiguration the person running steer has to see and the
    /// model does not, so it rides along with whatever the decision was and
    /// never becomes the decision. An allowed call that would have printed
    /// nothing prints the envelope for it.
    pub fn render(
        &self,
        event: Event,
        tool_input: &Value,
        decision: &Decision,
        note: Option<&str>,
    ) -> Answer {
        let verdict = self.verdict(tool_input, decision);
        match self.response {
            Response::Claude => {
                let mut fields = Map::new();
                fields.insert("hookEventName".into(), json!(event.as_str()));
                match verdict {
                    Verdict::Silent if note.is_none() => return Answer::stdout(None),
                    Verdict::Silent => {}
                    Verdict::Deny(reason) => {
                        fields.insert("permissionDecision".into(), json!("deny"));
                        fields.insert("permissionDecisionReason".into(), json!(reason));
                    }
                    Verdict::Update { input, message, .. } => {
                        // No `permissionDecision` alongside it: force-approving
                        // here would route a rewritten command around the
                        // permission classifier.
                        fields.insert("updatedInput".into(), input);
                        append(&mut fields, "systemMessage", &message);
                    }
                    Verdict::Context(message) => {
                        fields.insert("additionalContext".into(), json!(message));
                    }
                }
                append(&mut fields, "systemMessage", note.unwrap_or_default());
                Answer::stdout(Some(
                    json!({ "hookSpecificOutput": Value::Object(fields) }).to_string(),
                ))
            }
            Response::Junie => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Silent => {}
                    Verdict::Deny(reason) => {
                        fields.insert("decision".into(), json!("block"));
                        fields.insert("reason".into(), json!(reason));
                    }
                    Verdict::Update { input, message, .. } => {
                        fields.insert("updatedInput".into(), input);
                        append(&mut fields, "additionalContext", &message);
                    }
                    Verdict::Context(message) => {
                        fields.insert("additionalContext".into(), json!(message));
                    }
                }
                // Junie publishes no user-facing field, so the note reaches the
                // model or nobody. Inferred from the absence.
                append(&mut fields, "additionalContext", note.unwrap_or_default());
                Answer::stdout(body(fields))
            }
            Response::Gemini => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Deny(reason) => {
                        fields.insert("decision".into(), json!("deny"));
                        fields.insert("reason".into(), json!(reason));
                    }
                    Verdict::Update { input, message, .. } => {
                        fields.insert("hookSpecificOutput".into(), json!({ "tool_input": input }));
                        append(&mut fields, "systemMessage", &message);
                    }
                    // `hook` drops a `context` rule before a harness that
                    // cannot take one, so there is nothing left to place.
                    Verdict::Silent | Verdict::Context(_) => {}
                }
                append(&mut fields, "systemMessage", note.unwrap_or_default());
                Answer::stdout(body(fields))
            }
            Response::Cursor => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Deny(reason) => {
                        fields.insert("permission".into(), json!("deny"));
                        // `agent_message` rather than `user_message`: the model
                        // is what a deny has to convince, and Cursor shows the
                        // two to different readers.
                        fields.insert("agent_message".into(), json!(reason));
                    }
                    Verdict::Update { input, message, .. } => {
                        fields.insert("updated_input".into(), input);
                        append(&mut fields, "user_message", &message);
                    }
                    Verdict::Silent | Verdict::Context(_) => {}
                }
                // Both messages are documented for a denial only, so a note on
                // an allowed call may reach nobody. Inferred placement: it is
                // the field Cursor shows the person running steer, which is who
                // a misconfiguration is for.
                append(&mut fields, "user_message", note.unwrap_or_default());
                Answer::stdout(body(fields))
            }
            Response::Copilot => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Deny(reason) => {
                        fields.insert("permissionDecision".into(), json!("deny"));
                        fields.insert("permissionDecisionReason".into(), json!(reason));
                    }
                    Verdict::Update { input, message, .. } => {
                        fields.insert("modifiedArgs".into(), input);
                        append(&mut fields, "permissionDecisionReason", &message);
                    }
                    Verdict::Silent | Verdict::Context(_) => {}
                }
                // Copilot's reason is documented as shown to the agent, and it
                // publishes nothing addressed to the person running steer.
                append(
                    &mut fields,
                    "permissionDecisionReason",
                    note.unwrap_or_default(),
                );
                Answer::stdout(body(fields))
            }
            Response::Crush => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Deny(reason) => {
                        fields.insert("decision".into(), json!("deny"));
                        fields.insert("reason".into(), json!(reason));
                    }
                    // `context` is what Crush carries on an allowed call, so a
                    // rewrite's explanation and a `context` rule land in the
                    // same field.
                    Verdict::Update { input, message, .. } => {
                        fields.insert("updated_input".into(), input);
                        append(&mut fields, "context", &message);
                    }
                    Verdict::Context(message) => {
                        fields.insert("context".into(), json!(message));
                    }
                    Verdict::Silent => {}
                }
                append(&mut fields, "context", note.unwrap_or_default());
                if !fields.is_empty() {
                    fields.insert("version".into(), json!(1));
                }
                Answer::stdout(body(fields))
            }
            Response::Cline => {
                let mut fields = Map::new();
                match verdict {
                    Verdict::Deny(reason) => {
                        fields.insert("cancel".into(), json!(true));
                        fields.insert("errorMessage".into(), json!(reason));
                    }
                    Verdict::Context(message) => {
                        fields.insert("contextModification".into(), json!(message));
                    }
                    Verdict::Silent | Verdict::Update { .. } => {}
                }
                append(&mut fields, "contextModification", note.unwrap_or_default());
                // `cancel` carries the decision, so anything steer prints says
                // outright that it is not cancelling rather than leaving the
                // field to a default nobody documented.
                if !fields.is_empty() {
                    fields.entry("cancel").or_insert(json!(false));
                }
                Answer::stdout(body(fields))
            }
            Response::Windsurf => {
                let (reason, code) = match verdict {
                    Verdict::Deny(reason) => (Some(reason), 2),
                    Verdict::Silent | Verdict::Update { .. } | Verdict::Context(_) => (None, 0),
                };
                // Windsurf reads stderr as the deny reason. Whether it shows
                // stderr on an exit 0 is undocumented, so a note may go
                // nowhere — but there is no other channel to try.
                let stderr = match (reason, note) {
                    (Some(reason), Some(note)) => Some(format!("{reason}\n\n{note}")),
                    (reason, note) => reason.or_else(|| note.map(str::to_string)),
                };
                Answer {
                    stdout: None,
                    stderr,
                    code,
                }
            }
            Response::Neutral => {
                let mut fields = Map::new();
                match verdict {
                    // Said outright rather than left to an empty stdout. The
                    // shim reads silence as "let it through" because it has to
                    // fail open, so an allow steer meant and an allow steer
                    // fell over on would otherwise be the same answer.
                    //
                    // No shim harness takes a note before the call, so `hook`
                    // drops a `context` rule before it reaches here.
                    Verdict::Silent | Verdict::Context(_) => {
                        fields.insert("outcome".into(), json!("allow"));
                    }
                    Verdict::Deny(reason) => {
                        fields.insert("outcome".into(), json!("deny"));
                        fields.insert("message".into(), json!(reason));
                    }
                    Verdict::Update {
                        command, message, ..
                    } => {
                        fields.insert("outcome".into(), json!("rewrite"));
                        fields.insert("updated_command".into(), json!(command));
                        fields.insert("message".into(), json!(message));
                    }
                }
                append(&mut fields, "message", note.unwrap_or_default());
                Answer::stdout(body(fields))
            }
        }
    }

    fn verdict(&self, tool_input: &Value, decision: &Decision) -> Verdict {
        match decision.outcome {
            Outcome::Allow => Verdict::Silent,
            Outcome::Deny => Verdict::Deny(decision.message.clone()),
            Outcome::Context => Verdict::Context(decision.message.clone()),
            Outcome::Rewrite => {
                let Some(command) = decision.updated_command.clone() else {
                    return Verdict::Silent;
                };
                if !self.capabilities.rewrite {
                    let guidance = format!("Run this instead:\n\n  {command}");
                    let reason = match decision.message.is_empty() {
                        true => guidance,
                        false => format!("{}\n\n{guidance}", decision.message),
                    };
                    return Verdict::Deny(reason);
                }
                let mut input = tool_input.clone();
                if !self.ingest.splice(&mut input, &command) {
                    return Verdict::Silent;
                }
                Verdict::Update {
                    input,
                    command,
                    message: decision.message.clone(),
                }
            }
        }
    }
}

/// Nothing at all rather than an empty object, which every harness here would
/// read as a response it has to parse before finding no decision in it.
fn body(fields: Map<String, Value>) -> Option<String> {
    match fields.is_empty() {
        true => None,
        false => Some(Value::Object(fields).to_string()),
    }
}

/// Appends rather than assigns, because whichever field a harness shows the
/// user is the one a rewrite already speaks through.
fn append(fields: &mut Map<String, Value>, key: &str, note: &str) {
    if note.is_empty() {
        return;
    }
    let text = match fields.get(key).and_then(Value::as_str) {
        Some(message) => format!("{message}\n\n{note}"),
        None => note.to_string(),
    };
    fields.insert(key.into(), json!(text));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_encoded_tool_input_is_decoded_before_the_rules_read_it() {
        let ingest = Ingest {
            tools: &[("bash", "shell")],
            name: "/toolName",
            input: "/toolArgs",
            cwd: "/cwd",
            encoded: true,
            command: "command",
            path: &[],
            command_in: None,
        };
        let mut payload = json!({
            "toolName": "bash",
            "toolArgs": "{\"command\":\"rm -rf dist\",\"description\":\"clear the build\"}",
        });
        assert_eq!(
            ingest.normalize(ingest.read(&mut payload)),
            json!({ "command": "rm -rf dist", "description": "clear the build" })
        );
    }

    #[test]
    fn a_nested_command_lifts_out_and_splices_back_where_it_came_from() {
        let ingest = Ingest {
            tools: &[("run_command", "shell")],
            name: "/toolCall/name",
            input: "/toolCall",
            cwd: "/workspacePaths/0",
            encoded: false,
            command: "CommandLine",
            path: &[],
            command_in: Some("args"),
        };
        let mut payload = json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "rm -rf dist", "Blocking": true } },
            "workspacePaths": ["/repo"],
        });
        assert_eq!(ingest.tool_name(&payload), "run_command");
        assert_eq!(ingest.workspace(&payload), Some(PathBuf::from("/repo")));

        let raw = ingest.read(&mut payload);
        assert_eq!(
            ingest.normalize(raw.clone()),
            json!({
                "name": "run_command",
                "args": { "Blocking": true },
                "command": "rm -rf dist",
            })
        );

        let mut rewritten = raw;
        assert!(ingest.splice(&mut rewritten, "trash dist"));
        assert_eq!(
            rewritten,
            json!({
                "name": "run_command",
                "args": { "CommandLine": "trash dist", "Blocking": true },
            })
        );
    }
}

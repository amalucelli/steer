// Terminal furniture: colour, the label column every report aligns to, and the
// one thing a logged command needs before it can be printed at all.
//
// It sits apart from the commands because a report is read in two places. The
// same text is piped into `grep` and redirected into a config file, and an
// escape that survives that is a bug in whatever consumed it.

use crate::rules::Outcome;
use std::io::IsTerminal;

/// Colour is for the terminal only, so a piped `validate` stays greppable and
/// the tests read plain text.
pub struct Ink(bool);

impl Ink {
    pub fn new() -> Ink {
        Ink(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        match self.0 && !text.is_empty() {
            true => format!("\u{1b}[{code}m{text}\u{1b}[0m"),
            false => text.to_string(),
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.wrap("2", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }

    pub fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }

    pub fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }

    pub fn cyan(&self, text: &str) -> String {
        self.wrap("36", text)
    }
}

/// A label, then the value from column ten on: the longest label plus its gap.
pub fn row(ink: &Ink, label: &str, value: &str) {
    match value.is_empty() {
        true => println!("{}", ink.dim(label)),
        false => println!("{}{value}", ink.dim(&format!("{label:<10}"))),
    }
}

pub fn paint_outcome(ink: &Ink, outcome: Outcome) -> String {
    match outcome {
        Outcome::Deny => ink.red("deny"),
        Outcome::Rewrite => ink.yellow("rewrite"),
        Outcome::Context => ink.cyan("context"),
        Outcome::Allow => ink.green("allow"),
    }
}

/// A logged command can be a heredoc carrying a whole document, which is one
/// line in the file and a screenful on a terminal.
pub fn clip(command: &str) -> String {
    let flat = command.replace('\n', " ");
    match flat.char_indices().nth(120) {
        Some((cut, _)) => format!("{}…", &flat[..cut]),
        None => flat,
    }
}

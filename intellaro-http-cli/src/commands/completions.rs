//! Shell completion generation command.

use clap::{Command, Subcommand};
use clap_complete::{generate, Shell};

use crate::error::CliResult;

/// Shell completion subcommands.
#[derive(Debug, Subcommand)]
pub enum CompletionsCmd {
    /// Generate shell completion scripts.
    Generate {
        /// Target shell: bash, zsh, fish, powershell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// Execute the completions command.
pub fn execute(cmd: &CompletionsCmd, cli_command: &mut Command) -> CliResult<()> {
    match cmd {
        CompletionsCmd::Generate { shell } => {
            let name = cli_command.get_name().to_string();
            generate(*shell, cli_command, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

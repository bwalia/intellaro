//! Output formatting — table, JSON, and YAML renderers.
//!
//! All command modules call these helpers to render results in the
//! format the user requested via `--output`.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use colored::Colorize;

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table.
    Table,
    /// Machine-readable JSON.
    Json,
    /// Machine-readable YAML.
    Yaml,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Table
    }
}

// ── Structured output helpers ────────────────────────────────────────

/// Render a `serde_json::Value` in the requested format.
pub fn render_value(value: &serde_json::Value, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let pretty = serde_json::to_string_pretty(value).unwrap_or_default();
            println!("{pretty}");
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(value).unwrap_or_default();
            println!("{yaml}");
        }
        OutputFormat::Table => {
            // For generic JSON, fall back to pretty JSON since we
            // don't have column info. Specific commands use `render_table`.
            let pretty = serde_json::to_string_pretty(value).unwrap_or_default();
            println!("{pretty}");
        }
    }
}

/// Print a success message to stderr (keeps stdout clean for piping).
pub fn print_success(message: &str) {
    eprintln!("{} {}", "✔".green().bold(), message);
}

/// Print an error message to stderr.
pub fn print_error(message: &str) {
    eprintln!("{} {}", "✖".red().bold(), message);
}

/// Print an informational message to stderr.
pub fn print_info(message: &str) {
    eprintln!("{} {}", "ℹ".blue().bold(), message);
}

/// Print a warning message to stderr.
pub fn print_warn(message: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), message);
}

// ── Table rendering ──────────────────────────────────────────────────

/// Build and print a table with headers and rows.
///
/// # Example
/// ```ignore
/// render_table(
///     &["Name", "Address", "Weight"],
///     &[
///         vec!["backend-1", "10.0.0.1:80", "3"],
///         vec!["backend-2", "10.0.0.2:80", "1"],
///     ],
/// );
/// ```
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(
        headers
            .iter()
            .map(|h| Cell::new(h).fg(Color::Cyan))
            .collect::<Vec<_>>(),
    );

    for row in rows {
        table.add_row(row.iter().map(|c| Cell::new(c)).collect::<Vec<_>>());
    }

    println!("{table}");
}

/// Render a key-value detail view (for single-object display).
///
/// # Example
/// ```ignore
/// render_kv(&[
///     ("Version", "0.1.0"),
///     ("Listeners", "2"),
///     ("Upstreams", "3"),
/// ]);
/// ```
pub fn render_kv(pairs: &[(&str, &str)]) {
    let max_key_len = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

    for (key, value) in pairs {
        println!(
            "  {:<width$}  {}",
            key.cyan().bold(),
            value,
            width = max_key_len
        );
    }
}

// ── Diff rendering ───────────────────────────────────────────────────

/// Render a unified diff between two strings, with colorized output.
pub fn render_diff(label_a: &str, label_b: &str, text_a: &str, text_b: &str) {
    use similar::{ChangeTag, TextDiff};

    let diff = TextDiff::from_lines(text_a, text_b);

    println!("{}", format!("--- {label_a}").red());
    println!("{}", format!("+++ {label_b}").green());

    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => print!("{}", format!("-{change}").red()),
            ChangeTag::Insert => print!("{}", format!("+{change}").green()),
            ChangeTag::Equal => print!(" {change}"),
        }
    }
}

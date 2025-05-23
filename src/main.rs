mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sigil", version = "1.1.0", about = "Sigil Protocol CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Commit { input: String, output: String },
    Recover { archive: String, output: String },
    Embed { input: String, archive: String, output: String },
    Extract { input: String, output: String },
    Verify { archive: String },
    Derive { label: String },
    History { archive: String },
    Prune { archive: String, keep_latest: usize },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Commit { input, output } => commands::commit::run(&input, &output),
        Commands::Recover { archive, output } => commands::recover::run(&archive, &output),
        Commands::Embed { input, archive, output } => commands::embed::run(&input, &archive, &output),
        Commands::Extract { input, output } => commands::extract::run(&input, &output),
        Commands::Verify { archive } => commands::verify::run(&archive),
        Commands::Derive { label } => commands::derive::run(&label),
        Commands::History { archive } => commands::history::run(&archive),
        Commands::Prune { archive, keep_latest } => commands::prune::run(&archive, keep_latest),
    }
}
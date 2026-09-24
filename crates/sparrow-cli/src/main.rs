use clap::Parser;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sparrow",
    version,
    about = "Ingest Hawk / Microsoft-Extractor-Suite output into a DuckDB case database for M365 BEC investigations"
)]
struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
}

fn main() -> ExitCode {
    let _cli = Cli::parse();
    ExitCode::SUCCESS
}

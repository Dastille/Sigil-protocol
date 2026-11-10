use std::process::ExitCode;

fn main() -> ExitCode {
    match ratchet_measure::harness::run_cli(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ratchet-measure: {e}");
            ExitCode::FAILURE
        }
    }
}

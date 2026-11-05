use std::process::ExitCode;
#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match moon_naive::cli::run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!(
                "event=command_failed detail=configuration_private_files_trust_state_or_runtime; no secret values logged"
            );
            ExitCode::FAILURE
        }
    }
}

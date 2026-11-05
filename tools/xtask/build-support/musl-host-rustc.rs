//! Alpine build scripts must load libclang; only target artifacts use crt-static.
use std::{
    env,
    ffi::OsString,
    process::{Command, ExitCode},
};
fn main() -> ExitCode {
    let mut input = env::args_os().skip(1);
    let Some(rustc) = input.next() else {
        return ExitCode::FAILURE;
    };
    let mut args = input.collect::<Vec<OsString>>();
    if !args.iter().any(|arg| {
        arg == "--target" || arg.to_str().is_some_and(|arg| arg.starts_with("--target="))
    }) {
        args.push("-C".into());
        args.push("target-feature=-crt-static".into());
    }
    match Command::new(rustc).args(args).status() {
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        ),
        Err(_) => ExitCode::FAILURE,
    }
}

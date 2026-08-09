// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

use std::env;
use std::path::Path;
use std::process::ExitCode;

use filebelt_transcoder::LocalTranscodePlan;

fn main() -> ExitCode {
    let plan = match LocalTranscodePlan::parse(env::args_os().skip(1)) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("invalid FileBelt transcode plan: {error:?}");
            return ExitCode::from(64);
        }
    };
    match plan
        .ffmpeg_command(Path::new("/usr/local/bin/ffmpeg"))
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("unable to invoke approved FFmpeg binary: {error}");
            ExitCode::from(70)
        }
    }
}

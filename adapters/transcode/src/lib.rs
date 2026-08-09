// SPDX-License-Identifier: GPL-3.0-or-later

//! The GPL FFmpeg wrapper accepts only a controller-issued local execution
//! plan. It has no database client, payload mount API, browser/session input,
//! network endpoint, or shell interpolation.

#![deny(unsafe_code)]

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const MAXIMUM_DURATION_SECONDS: u64 = 4 * 60 * 60;
const INPUT_ROOT: &str = "/work/input";
const OUTPUT_ROOT: &str = "/work/output";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Av1Opus,
    Vp9Opus,
}

impl Profile {
    pub fn parse(value: &str) -> Result<Self, WrapperError> {
        match value {
            "av1-opus" => Ok(Self::Av1Opus),
            "vp9-opus" => Ok(Self::Vp9Opus),
            _ => Err(WrapperError::UnsupportedProfile),
        }
    }

    fn video_encoder(self) -> &'static str {
        match self {
            Self::Av1Opus => "libaom-av1",
            Self::Vp9Opus => "libvpx-vp9",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTranscodePlan {
    pub input: PathBuf,
    pub output: PathBuf,
    pub profile: Profile,
    pub maximum_duration_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapperError {
    InvalidArgument,
    InvalidPath,
    MissingArgument,
    UnsupportedProfile,
    DurationExceeded,
}

impl LocalTranscodePlan {
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, WrapperError> {
        let mut input = None;
        let mut output = None;
        let mut profile = None;
        let mut maximum_duration_seconds = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let value = argument.to_str().ok_or(WrapperError::InvalidArgument)?;
            match value {
                "--input" if input.is_none() => {
                    input = Some(PathBuf::from(next_argument(&mut arguments)?))
                }
                "--output" if output.is_none() => {
                    output = Some(PathBuf::from(next_argument(&mut arguments)?))
                }
                "--profile" if profile.is_none() => {
                    profile = Some(Profile::parse(&next_argument(&mut arguments)?)?)
                }
                "--maximum-duration-seconds" if maximum_duration_seconds.is_none() => {
                    maximum_duration_seconds = Some(
                        next_argument(&mut arguments)?
                            .parse::<u64>()
                            .map_err(|_| WrapperError::InvalidArgument)?,
                    );
                }
                _ => return Err(WrapperError::InvalidArgument),
            }
        }
        let plan = Self {
            input: input.ok_or(WrapperError::MissingArgument)?,
            output: output.ok_or(WrapperError::MissingArgument)?,
            profile: profile.ok_or(WrapperError::MissingArgument)?,
            maximum_duration_seconds: maximum_duration_seconds
                .ok_or(WrapperError::MissingArgument)?,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), WrapperError> {
        local_path(&self.input, INPUT_ROOT)?;
        local_path(&self.output, OUTPUT_ROOT)?;
        if self.maximum_duration_seconds == 0
            || self.maximum_duration_seconds > MAXIMUM_DURATION_SECONDS
        {
            return Err(WrapperError::DurationExceeded);
        }
        Ok(())
    }

    /// Produces one argument-vector invocation. `Command` never invokes a
    /// shell, so untrusted media names cannot become options or commands.
    #[must_use]
    pub fn ffmpeg_command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .arg("-nostdin")
            .arg("-hide_banner")
            .arg("-loglevel")
            .arg("error")
            .arg("-xerror")
            .arg("-protocol_whitelist")
            .arg("file,pipe")
            .arg("-i")
            .arg(&self.input)
            .arg("-map")
            .arg("0:v:0")
            .arg("-map")
            .arg("0:a:0?")
            .arg("-c:v")
            .arg(self.profile.video_encoder())
            .arg("-c:a")
            .arg("libopus")
            .arg("-t")
            .arg(self.maximum_duration_seconds.to_string())
            .arg(&self.output);
        command
    }
}

fn next_argument(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, WrapperError> {
    arguments
        .next()
        .and_then(|candidate| candidate.into_string().ok())
        .ok_or(WrapperError::MissingArgument)
}

fn local_path(value: &Path, root: &str) -> Result<(), WrapperError> {
    if !value.starts_with(root)
        || value == Path::new(root)
        || value.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(WrapperError::InvalidPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(profile: Profile) -> LocalTranscodePlan {
        LocalTranscodePlan {
            input: PathBuf::from("/work/input/source"),
            output: PathBuf::from("/work/output/segment"),
            profile,
            maximum_duration_seconds: 60,
        }
    }

    #[test]
    fn accepts_only_the_admitted_av1_or_vp9_profiles_with_opus() {
        assert_eq!(Profile::parse("av1-opus"), Ok(Profile::Av1Opus));
        assert_eq!(Profile::parse("vp9-opus"), Ok(Profile::Vp9Opus));
        assert_eq!(
            Profile::parse("h264-aac"),
            Err(WrapperError::UnsupportedProfile)
        );
    }

    #[test]
    fn confines_all_media_paths_to_the_emptydir_contract() {
        assert!(plan(Profile::Vp9Opus).validate().is_ok());
        assert_eq!(
            LocalTranscodePlan {
                input: PathBuf::from("/work/input/../output/escape"),
                ..plan(Profile::Vp9Opus)
            }
            .validate(),
            Err(WrapperError::InvalidPath)
        );
        assert_eq!(
            LocalTranscodePlan {
                output: PathBuf::from("/payload/output"),
                ..plan(Profile::Vp9Opus)
            }
            .validate(),
            Err(WrapperError::InvalidPath)
        );
    }

    #[test]
    fn invokes_ffmpeg_without_network_protocols_or_a_shell() {
        let command = plan(Profile::Av1Opus).ffmpeg_command(Path::new("/usr/bin/ffmpeg"));
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["-protocol_whitelist", "file,pipe"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["-c:v", "libaom-av1"])
        );
        assert!(arguments.windows(2).any(|pair| pair == ["-c:a", "libopus"]));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("http") || argument.contains("tcp"))
        );
    }

    #[test]
    fn rejects_duplicate_or_unrecognized_options() {
        let arguments = [
            "--input",
            "/work/input/source",
            "--input",
            "/work/input/second",
            "--output",
            "/work/output/result",
            "--profile",
            "vp9-opus",
            "--maximum-duration-seconds",
            "1",
        ]
        .map(OsString::from);
        assert_eq!(
            LocalTranscodePlan::parse(arguments),
            Err(WrapperError::InvalidArgument)
        );
    }
}

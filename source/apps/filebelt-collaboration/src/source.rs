// SPDX-License-Identifier: Apache-2.0

//! Strict Markdown byte decoding and reversible source formatting metadata.

use thiserror::Error;

use crate::MAX_MARKDOWN_SOURCE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineEnding {
    Lf,
    CrLf,
    Mixed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkdownSource {
    pub text: String,
    pub bom: bool,
    pub line_ending: LineEnding,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MarkdownSourceError {
    #[error("the Markdown source exceeds the editor limit")]
    TooLarge,
    #[error("the Markdown source is not valid UTF-8")]
    InvalidUtf8,
    #[error("the Markdown source contains a NUL byte")]
    ContainsNul,
}

impl MarkdownSource {
    pub fn decode(bytes: &[u8]) -> Result<Self, MarkdownSourceError> {
        if bytes.len() > MAX_MARKDOWN_SOURCE_BYTES {
            return Err(MarkdownSourceError::TooLarge);
        }
        let (bom, content) = match bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
            Some(content) => (true, content),
            None => (false, bytes),
        };
        if content.contains(&0) {
            return Err(MarkdownSourceError::ContainsNul);
        }
        let source = std::str::from_utf8(content).map_err(|_| MarkdownSourceError::InvalidUtf8)?;
        let mut saw_lf = false;
        let mut saw_crlf = false;
        let mut normalized = String::with_capacity(source.len());
        let mut characters = source.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\r' if characters.peek() == Some(&'\n') => {
                    characters.next();
                    normalized.push('\n');
                    saw_crlf = true;
                }
                '\n' => {
                    normalized.push('\n');
                    saw_lf = true;
                }
                other => normalized.push(other),
            }
        }
        let line_ending = match (saw_lf, saw_crlf) {
            (false, true) => LineEnding::CrLf,
            (true, true) => LineEnding::Mixed,
            _ => LineEnding::Lf,
        };
        Ok(Self {
            text: normalized,
            bom,
            line_ending,
        })
    }

    #[must_use]
    pub fn encode_for_save(&self) -> Vec<u8> {
        let use_crlf = self.line_ending == LineEnding::CrLf;
        let newline_count = self.text.bytes().filter(|byte| *byte == b'\n').count();
        let mut bytes = Vec::with_capacity(
            self.text.len() + usize::from(self.bom) * 3 + usize::from(use_crlf) * newline_count,
        );
        if self.bom {
            bytes.extend_from_slice(&[0xef, 0xbb, 0xbf]);
        }
        if use_crlf {
            for segment in self.text.split_inclusive('\n') {
                if let Some(content) = segment.strip_suffix('\n') {
                    bytes.extend_from_slice(content.as_bytes());
                    bytes.extend_from_slice(b"\r\n");
                } else {
                    bytes.extend_from_slice(segment.as_bytes());
                }
            }
        } else {
            bytes.extend_from_slice(self.text.as_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_uniform_line_endings_and_bom() {
        let source = MarkdownSource::decode(b"\xef\xbb\xbfhello\r\nworld\r\n").unwrap();
        assert!(source.bom);
        assert_eq!(source.line_ending, LineEnding::CrLf);
        assert_eq!(source.text, "hello\nworld\n");
        assert_eq!(source.encode_for_save(), b"\xef\xbb\xbfhello\r\nworld\r\n");
    }

    #[test]
    fn mixed_line_endings_are_normalized_to_lf_on_save() {
        let source = MarkdownSource::decode(b"one\r\ntwo\nthree").unwrap();
        assert_eq!(source.line_ending, LineEnding::Mixed);
        assert_eq!(source.encode_for_save(), b"one\ntwo\nthree");
    }

    #[test]
    fn rejects_invalid_utf8_and_nul() {
        assert_eq!(
            MarkdownSource::decode(&[0xff]),
            Err(MarkdownSourceError::InvalidUtf8)
        );
        assert_eq!(
            MarkdownSource::decode(b"bad\0source"),
            Err(MarkdownSourceError::ContainsNul)
        );
    }

    #[test]
    fn accepts_the_shared_sixteen_mib_editor_ceiling_exactly() {
        let source = vec![b'x'; MAX_MARKDOWN_SOURCE_BYTES];
        assert_eq!(
            MarkdownSource::decode(&source).unwrap().text.len(),
            MAX_MARKDOWN_SOURCE_BYTES
        );
        let oversized = vec![b'x'; MAX_MARKDOWN_SOURCE_BYTES + 1];
        assert_eq!(
            MarkdownSource::decode(&oversized),
            Err(MarkdownSourceError::TooLarge)
        );
    }
}

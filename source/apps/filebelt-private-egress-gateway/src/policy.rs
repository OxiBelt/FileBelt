// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use http::header::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use url::Url;

const TARGET_HEADER: &str = "x-filebelt-mcp-target";
const TRUST_HEADER: &str = "x-filebelt-mcp-trust-profile";
const METHOD_HEADER: &str = "x-filebelt-mcp-upstream-method";
const MCP_PROTOCOL_HEADER: &str = "mcp-protocol-version";
const MCP_SESSION_HEADER: &str = "mcp-session-id";
const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidControl,
    TargetDenied,
    MethodDenied,
    PathDenied,
    RequestTooLarge,
    ResponseDenied,
}

impl PolicyError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidControl => "gateway.control.invalid",
            Self::TargetDenied => "gateway.target.denied",
            Self::MethodDenied => "gateway.method.denied",
            Self::PathDenied => "gateway.path.denied",
            Self::RequestTooLarge => "gateway.request.too_large",
            Self::ResponseDenied => "gateway.response.denied",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TargetDenied | Self::MethodDenied | Self::PathDenied => StatusCode::FORBIDDEN,
            Self::InvalidControl | Self::ResponseDenied => StatusCode::BAD_REQUEST,
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Debug)]
pub struct McpRequestPolicy {
    target: Url,
    trust_profile: String,
}

#[derive(Clone, Debug)]
pub struct AdmittedMcpRequest {
    pub method: Method,
    pub target: Url,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl McpRequestPolicy {
    pub fn new(target: Url, trust_profile: String) -> Self {
        Self {
            target,
            trust_profile,
        }
    }

    pub fn admit(&self, headers: &HeaderMap) -> Result<AdmittedMcpRequest, PolicyError> {
        reject_transfer_coding(headers)?;
        let target = required_single_header(headers, TARGET_HEADER)?;
        let parsed = Url::parse(target).map_err(|_| PolicyError::TargetDenied)?;
        if parsed.as_str() != target || parsed != self.target {
            return Err(PolicyError::TargetDenied);
        }
        if required_single_header(headers, TRUST_HEADER)? != self.trust_profile {
            return Err(PolicyError::TargetDenied);
        }
        let method = match required_single_header(headers, METHOD_HEADER)? {
            "GET" => Method::GET,
            "POST" => Method::POST,
            _ => return Err(PolicyError::MethodDenied),
        };
        let mut forwarded = Vec::new();
        for name in [
            AUTHORIZATION,
            HeaderName::from_static(API_KEY_HEADER),
            HeaderName::from_static(MCP_PROTOCOL_HEADER),
            HeaderName::from_static(MCP_SESSION_HEADER),
            CONTENT_TYPE,
            ACCEPT,
        ] {
            let values = headers.get_all(&name);
            let mut values = values.iter();
            if let Some(value) = values.next() {
                if values.next().is_some() {
                    return Err(PolicyError::InvalidControl);
                }
                forwarded.push((name, value.clone()));
            }
        }
        Ok(AdmittedMcpRequest {
            method,
            target: self.target.clone(),
            headers: forwarded,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OnlyofficeRequestPolicy {
    origin: Url,
    path_prefix: String,
    response_limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlyofficeFetchRequest {
    pub url: String,
    pub maximum_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct AdmittedOnlyofficeRequest {
    pub target: Url,
    pub maximum_bytes: usize,
}

impl OnlyofficeRequestPolicy {
    pub fn new(origin: Url, path_prefix: String, response_limit: usize) -> Self {
        Self {
            origin,
            path_prefix,
            response_limit,
        }
    }

    pub fn admit(
        &self,
        headers: &HeaderMap,
        request: &OnlyofficeFetchRequest,
    ) -> Result<AdmittedOnlyofficeRequest, PolicyError> {
        reject_transfer_coding(headers)?;
        let target = Url::parse(&request.url).map_err(|_| PolicyError::TargetDenied)?;
        if target.as_str() != request.url
            || target.scheme() != "https"
            || target.origin() != self.origin.origin()
            || !target.username().is_empty()
            || target.password().is_some()
            || target.fragment().is_some()
        {
            return Err(PolicyError::TargetDenied);
        }
        if !target.path().starts_with(&self.path_prefix) || has_ambiguous_path_encoding(&target) {
            return Err(PolicyError::PathDenied);
        }
        let maximum_bytes = usize::try_from(request.maximum_bytes)
            .ok()
            .filter(|size| (1..=self.response_limit).contains(size))
            .ok_or(PolicyError::RequestTooLarge)?;
        Ok(AdmittedOnlyofficeRequest {
            target,
            maximum_bytes,
        })
    }
}

pub fn admit_response_status(status: StatusCode) -> Result<(), PolicyError> {
    if status.is_redirection() {
        return Err(PolicyError::ResponseDenied);
    }
    Ok(())
}

fn reject_transfer_coding(headers: &HeaderMap) -> Result<(), PolicyError> {
    if headers.contains_key(TRANSFER_ENCODING) || headers.contains_key(CONTENT_ENCODING) {
        return Err(PolicyError::InvalidControl);
    }
    Ok(())
}

fn required_single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, PolicyError> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let value = values.next().ok_or(PolicyError::InvalidControl)?;
    if values.next().is_some() {
        return Err(PolicyError::InvalidControl);
    }
    value.to_str().map_err(|_| PolicyError::InvalidControl)
}

fn has_ambiguous_path_encoding(url: &Url) -> bool {
    let bytes = url.path().as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' || bytes[index].is_ascii_control() {
            return true;
        }
        if bytes[index] == b'%' {
            let Some(encoded) = bytes.get(index + 1..index + 3) else {
                return true;
            };
            let Ok(encoded) = std::str::from_utf8(encoded) else {
                return true;
            };
            let Ok(decoded) = u8::from_str_radix(encoded, 16) else {
                return true;
            };
            if decoded <= 0x20 || matches!(decoded, b'#' | b'%' | b'.' | b'/' | b'?' | b'\\' | 0x7f)
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp_policy() -> McpRequestPolicy {
        McpRequestPolicy::new(
            Url::parse("https://llm.private.example/mcp").unwrap(),
            "private-ca-v1".into(),
        )
    }

    fn mcp_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            TARGET_HEADER,
            "https://llm.private.example/mcp".parse().unwrap(),
        );
        headers.insert(TRUST_HEADER, "private-ca-v1".parse().unwrap());
        headers.insert(METHOD_HEADER, "POST".parse().unwrap());
        headers.insert(AUTHORIZATION, "Bearer sensitive".parse().unwrap());
        headers.insert("cookie", "must-not-forward".parse().unwrap());
        headers
    }

    #[test]
    fn mcp_requires_exact_canonical_target_trust_and_method() {
        assert!(mcp_policy().admit(&mcp_headers()).is_ok());
        for (name, value) in [
            (TARGET_HEADER, "https://metadata.invalid/mcp"),
            (TARGET_HEADER, "https://llm.private.example:443/mcp"),
            (TRUST_HEADER, "public-webpki"),
            (METHOD_HEADER, "CONNECT"),
        ] {
            let mut headers = mcp_headers();
            headers.insert(name, value.parse().unwrap());
            assert!(mcp_policy().admit(&headers).is_err());
        }
    }

    #[test]
    fn mcp_forwards_only_the_broker_protocol_allowlist() {
        let admitted = mcp_policy().admit(&mcp_headers()).unwrap();
        assert!(
            admitted
                .headers
                .iter()
                .any(|(name, _)| name == AUTHORIZATION)
        );
        assert!(!admitted.headers.iter().any(|(name, _)| name == "cookie"));
        assert!(
            !admitted
                .headers
                .iter()
                .any(|(name, _)| name == TARGET_HEADER)
        );
    }

    fn onlyoffice_policy() -> OnlyofficeRequestPolicy {
        OnlyofficeRequestPolicy::new(
            Url::parse("https://document.private.example/").unwrap(),
            "/cache/files/".into(),
            100 * 1024 * 1024,
        )
    }

    fn fetch(url: &str) -> OnlyofficeFetchRequest {
        OnlyofficeFetchRequest {
            url: url.into(),
            maximum_bytes: 100 * 1024 * 1024,
        }
    }

    #[test]
    fn onlyoffice_rejects_ssrf_origin_and_path_escape() {
        let headers = HeaderMap::new();
        assert!(
            onlyoffice_policy()
                .admit(
                    &headers,
                    &fetch("https://document.private.example/cache/files/output.docx?token=x"),
                )
                .is_ok()
        );
        for target in [
            "https://169.254.169.254/cache/files/output.docx",
            "https://document.private.example/other/output.docx",
            "https://document.private.example/cache/files/%2e%2e/private",
            "https://document.private.example/cache/files/%252e%252e%252fprivate",
            "https://document.private.example/cache/files%2fprivate",
            "https://document.private.example/cache/files/output.docx#fragment",
        ] {
            assert!(
                onlyoffice_policy().admit(&headers, &fetch(target)).is_err(),
                "target unexpectedly admitted"
            );
        }
    }

    #[test]
    fn onlyoffice_enforces_requested_and_absolute_response_limit() {
        let mut request = fetch("https://document.private.example/cache/files/output.docx");
        request.maximum_bytes += 1;
        assert!(
            onlyoffice_policy()
                .admit(&HeaderMap::new(), &request)
                .is_err()
        );
    }

    #[test]
    fn redirect_is_never_followed_or_returned() {
        assert!(admit_response_status(StatusCode::FOUND).is_err());
        assert!(admit_response_status(StatusCode::OK).is_ok());
    }

    #[test]
    fn errors_never_render_request_values() {
        for error in [
            PolicyError::InvalidControl,
            PolicyError::TargetDenied,
            PolicyError::MethodDenied,
            PolicyError::PathDenied,
            PolicyError::RequestTooLarge,
            PolicyError::ResponseDenied,
        ] {
            let rendered = error.to_string();
            assert_eq!(rendered, error.code());
            assert!(!rendered.contains("https://"));
        }
    }
}

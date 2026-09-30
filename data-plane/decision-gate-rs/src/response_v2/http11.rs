use crate::{
    ImmutableObjectReference, ImmutableObjectType, V2Http11FramingResultV1,
    V2Http11TransferCodingV1,
    V2ParsedHttp11ResponseCommitmentV1,
    RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAX_V2_HTTP_HEAD_BYTES: usize = 256 * 1024;
const MAX_V2_HTTP_HEADERS: usize = 1024;
const MAX_V2_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_V2_CHUNKS: usize = 65_536;

pub(crate) struct StrictHttp11Response {
    // Actual final physical Content-Type, not a reconstructed header map.
    // Err means ambiguous/non-ASCII/oversized; it does not reject old parsers.
    pub(crate) content_type: Result<Option<String>, ()>,
    pub(crate) status: u16,
    pub(crate) keep_alive: bool,
    pub(crate) entity_body: Zeroizing<Vec<u8>>,
    pub(crate) framing: V2Http11FramingResultV1,
    pub(crate) parsed_response:
        V2ParsedHttp11ResponseCommitmentV1,
}

pub(crate) fn response_observation_v2_finalized_keep_alive(
    response: &[u8],
) -> Result<bool, String> {
    Ok(response_observation_v2_parse_http11(
        response,
        None,
    )?
    .keep_alive)
}

pub(crate) fn response_observation_v2_parse_immutable_http11(
    response: &[u8],
    immutable: &ImmutableObjectReference,
    request_method: &str,
) -> Result<StrictHttp11Response, String> {
    if immutable.object_type != ImmutableObjectType::ReleasedResponse
        || u64::try_from(response.len()).ok()
            != Some(immutable.byte_length)
        || http11_sha256_prefixed(response) != immutable.object_sha256
        || immutable.retrieval_id.is_empty()
        || !http11_is_sha256_digest(
            &immutable.persistence_receipt_sha256,
        )
    {
        return Err(
            "response-observation v2 bytes were not committed as the exact immutable released object"
                .to_string(),
        );
    }
    response_observation_v2_parse_http11(
        response,
        Some(request_method),
    )
}

pub(crate) fn response_observation_v2_parse_http11(
    response: &[u8],
    request_method: Option<&str>,
) -> Result<StrictHttp11Response, String> {
    if response.is_empty()
        || response.len()
            > RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES as usize
    {
        return Err(
            "response-observation v2 HTTP response is empty or exceeds the exact-object limit"
                .to_string(),
        );
    }
    let mut cursor = 0usize;
    let mut informational_statuses = Vec::new();
    let mut header_section_length = 0u64;
    loop {
        let (status, headers, after_head, head_length) =
            response_observation_v2_parse_head(response, cursor)?;
        header_section_length = header_section_length
            .checked_add(head_length)
            .ok_or(
                "response-observation v2 cumulative head length overflow",
            )?;
        cursor = after_head;
        if headers.contains_key("upgrade")
            || headers.contains_key("proxy-connection")
        {
            return Err(
                "response-observation v2 rejects upgrade and proxy connection response fields"
                    .to_string(),
            );
        }
        if (100..200).contains(&status) {
            if status == 101 {
                return Err(
                    "response-observation v2 does not permit protocol upgrades"
                        .to_string(),
                );
            }
            informational_statuses.push(status);
            if informational_statuses.len()
                > MAX_V2_INFORMATIONAL_RESPONSES
                || headers.contains_key("content-length")
                || headers.contains_key("transfer-encoding")
                || headers.contains_key("trailer")
                || cursor == response.len()
            {
                return Err(
                    "response-observation v2 informational response framing is invalid"
                        .to_string(),
                );
            }
            continue;
        }
        let connection_tokens =
            response_observation_v2_csv_tokens(
                headers.get("connection"),
                "connection",
            )?;
        if connection_tokens.iter().any(|token| {
            token != "close" && token != "keep-alive"
        }) || connection_tokens.contains(&"close".to_owned())
            && connection_tokens.contains(&"keep-alive".to_owned())
        {
            return Err(
                "response-observation v2 connection semantics are ambiguous"
                    .to_string(),
            );
        }
        let keep_alive =
            !connection_tokens.contains(&"close".to_owned());
        let content_length =
            response_observation_v2_content_length(
                headers.get("content-length"),
            )?;
        let transfer_codings =
            response_observation_v2_csv_tokens(
                headers.get("transfer-encoding"),
                "transfer-encoding",
            )?;
        if content_length.is_some() && !transfer_codings.is_empty() {
            return Err(
                "response-observation v2 forbids Content-Length with Transfer-Encoding"
                    .to_string(),
            );
        }
        if transfer_codings.is_empty()
            && headers.contains_key("trailer")
        {
            return Err(
                "response-observation v2 Trailer requires chunked framing"
                    .to_string(),
            );
        }
        if !transfer_codings.is_empty()
            && (transfer_codings.len() != 1
                || transfer_codings[0] != "chunked")
        {
            return Err(
                "response-observation v2 supports only a single final chunked transfer coding"
                    .to_string(),
            );
        }
        let is_head = request_method
            .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
        if request_method.is_some_and(|method| {
            method.eq_ignore_ascii_case("CONNECT")
        }) && (200..300).contains(&status)
        {
            return Err(
                "response-observation v2 does not release HTTP tunnel responses"
                    .to_string(),
            );
        }
        let previously_validated_unknown_method_no_body =
            request_method.is_none() && cursor == response.len();
        let content_type = match headers.get("content-type") {
            None => Ok(None),
            Some(values) if values.len() == 1 && values[0].len() <= 1024 && values[0].is_ascii() =>
                std::str::from_utf8(&values[0]).map(|value|Some(value.to_string())).map_err(|_|()),
            Some(_) => Err(()),
        };
        let no_body = is_head
            || status == 204
            || status == 205
            || status == 304
            || previously_validated_unknown_method_no_body;
        if no_body {
            if !transfer_codings.is_empty()
                || (status == 204 && content_length.is_some())
                || (status == 205
                    && content_length
                        .is_some_and(|length| length != 0))
                || cursor != response.len()
            {
                return Err(
                    "response-observation v2 no-body response carries framing or surplus bytes"
                        .to_string(),
                );
            }
            return response_observation_v2_finish_http11(
                response,
                status,
                keep_alive,
                informational_statuses,
                header_section_length,
                V2Http11TransferCodingV1::NoBody,
                content_length,
                0,
                Vec::new(),
                Zeroizing::new(Vec::new()),
                content_type,
            );
        }
        let (
            transfer_coding,
            trailer_section_length,
            trailer_names,
            entity_body,
        ) = if !transfer_codings.is_empty() {
            let declared_trailers =
                response_observation_v2_csv_tokens(
                    headers.get("trailer"),
                    "trailer",
                )?;
            let (body, consumed, trailer_length, trailer_names) =
                response_observation_v2_parse_chunked(
                    &response[cursor..],
                    &declared_trailers,
                )?;
            cursor = cursor
                .checked_add(consumed)
                .ok_or("response-observation v2 chunk cursor overflow")?;
            (
                V2Http11TransferCodingV1::Chunked,
                trailer_length,
                trailer_names,
                body,
            )
        } else if let Some(length) = content_length {
            let length = usize::try_from(length).map_err(|_| {
                "response-observation v2 Content-Length exceeds the platform"
                    .to_string()
            })?;
            let end = cursor.checked_add(length).ok_or(
                "response-observation v2 body length overflow",
            )?;
            if end > response.len() {
                return Err(
                    "response-observation v2 response body is truncated"
                        .to_string(),
                );
            }
            let body = Zeroizing::new(response[cursor..end].to_vec());
            cursor = end;
            (
                V2Http11TransferCodingV1::Identity,
                0,
                Vec::new(),
                body,
            )
        } else {
            return Err(
                "response-observation v2 rejects close-delimited responses until an authority-signed exact EOF contract is available"
                    .to_string(),
            );
        };
        if cursor != response.len() {
            return Err(
                "response-observation v2 response has surplus bytes after the final message"
                    .to_string(),
            );
        }
        return response_observation_v2_finish_http11(
            response,
            status,
            keep_alive,
            informational_statuses,
            header_section_length,
            transfer_coding,
            content_length,
            trailer_section_length,
            trailer_names,
            entity_body,
            content_type,
        );
    }
}

fn response_observation_v2_finish_http11(
    response: &[u8],
    status: u16,
    keep_alive: bool,
    informational_statuses: Vec<u16>,
    header_section_length: u64,
    transfer_coding: V2Http11TransferCodingV1,
    declared_content_length: Option<u64>,
    trailer_section_length: u64,
    trailer_names: Vec<String>,
    entity_body: Zeroizing<Vec<u8>>,
    content_type: Result<Option<String>, ()>,
) -> Result<StrictHttp11Response, String> {
    let decoded_entity_length =
        u64::try_from(entity_body.len()).map_err(|_| {
            "response-observation v2 decoded entity length overflows"
                .to_string()
        })?;
    let physical_message_length =
        u64::try_from(response.len()).map_err(|_| {
            "response-observation v2 physical message length overflows"
                .to_string()
        })?;
    let mut framing = V2Http11FramingResultV1 {
        http_version: "HTTP/1.1".to_owned(),
        informational_statuses,
        final_status: status,
        header_section_length,
        transfer_coding,
        declared_content_length,
        decoded_entity_length,
        trailer_section_length,
        trailer_names,
        physical_message_length,
        surplus_length: 0,
        canonical_framing_sha256: String::new(),
    };
    let framing_preimage =
        http11_canonical_json_bytes(&framing).map_err(|_| {
            "canonicalize response-observation v2 framing result"
                .to_string()
        })?;
    framing.canonical_framing_sha256 =
        http11_sha256_prefixed(&framing_preimage);
    let parsed_response =
        V2ParsedHttp11ResponseCommitmentV1 {
            api_version:
                "serverware.responseObservationV2ParsedHttp11Response/v1"
                    .to_owned(),
            raw_response_sha256: http11_sha256_prefixed(response),
            raw_response_byte_length: physical_message_length,
            framing_validation_sha256:
                framing.canonical_framing_sha256.clone(),
            final_status: status,
            decoded_entity_sha256:
                http11_sha256_prefixed(&entity_body),
            decoded_entity_length,
        };
    Ok(StrictHttp11Response {
        content_type,
        status,
        keep_alive,
        entity_body,
        framing,
        parsed_response,
    })
}

fn response_observation_v2_parse_head(
    response: &[u8],
    start: usize,
) -> Result<
    (u16, BTreeMap<String, Vec<Vec<u8>>>, usize, u64),
    String,
> {
    let relative_end = response
        .get(start..)
        .ok_or("response-observation v2 head cursor is invalid")?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(
            "response-observation v2 requires a complete HTTP/1.1 head",
        )?;
    let end = start
        .checked_add(relative_end)
        .ok_or("response-observation v2 head length overflow")?;
    let after_head = end
        .checked_add(4)
        .ok_or("response-observation v2 head cursor overflow")?;
    let head_line_end = end
        .checked_add(2)
        .ok_or("response-observation v2 head line overflow")?;
    let head_length = after_head
        .checked_sub(start)
        .ok_or("response-observation v2 head length underflow")?;
    if head_length > MAX_V2_HTTP_HEAD_BYTES {
        return Err(
            "response-observation v2 HTTP head exceeds its bound"
                .to_string(),
        );
    }
    let head = &response[start..head_line_end];
    let mut lines =
        head[..head.len() - 1].split(|byte| *byte == b'\n');
    let status_line = lines
        .next()
        .ok_or("response-observation v2 status line is missing")?;
    let status_line = status_line
        .strip_suffix(b"\r")
        .ok_or("response-observation v2 status line requires CRLF")?;
    if !status_line.starts_with(b"HTTP/1.1 ")
        || status_line.len() < 13
        || !status_line[9..12]
            .iter()
            .all(u8::is_ascii_digit)
        || status_line[12] != b' '
        || status_line.iter().any(|byte| {
            *byte == 0
                || *byte == b'\t'
                || (!byte.is_ascii_graphic() && *byte != b' ')
        })
    {
        return Err(
            "response-observation v2 status line is not strict HTTP/1.1"
                .to_string(),
        );
    }
    let status = std::str::from_utf8(&status_line[9..12])
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..600).contains(value))
        .ok_or("response-observation v2 status code is invalid")?;
    let mut headers: BTreeMap<String, Vec<Vec<u8>>> =
        BTreeMap::new();
    let mut count = 0usize;
    for raw_line in lines {
        let line = raw_line
            .strip_suffix(b"\r")
            .ok_or(
                "response-observation v2 header line requires CRLF",
            )?;
        if line.is_empty()
            || line[0] == b' '
            || line[0] == b'\t'
        {
            return Err(
                "response-observation v2 rejects empty or folded header lines"
                    .to_string(),
            );
        }
        count = count.saturating_add(1);
        if count > MAX_V2_HTTP_HEADERS {
            return Err(
                "response-observation v2 header count exceeds its bound"
                    .to_string(),
            );
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or("response-observation v2 header lacks a colon")?;
        let name = &line[..colon];
        if name.is_empty()
            || !name.iter().copied().all(is_http_token_byte)
        {
            return Err(
                "response-observation v2 header name is invalid"
                    .to_string(),
            );
        }
        let mut value = &line[colon + 1..];
        while value.first().is_some_and(|byte| {
            *byte == b' ' || *byte == b'\t'
        }) {
            value = &value[1..];
        }
        while value.last().is_some_and(|byte| {
            *byte == b' ' || *byte == b'\t'
        }) {
            value = &value[..value.len() - 1];
        }
        if value.iter().any(|byte| {
            *byte == 0
                || *byte == b'\r'
                || *byte == b'\n'
                || (*byte < 0x20 && *byte != b'\t')
                || *byte == 0x7f
        }) {
            return Err(
                "response-observation v2 header value is invalid"
                    .to_string(),
            );
        }
        headers
            .entry(
                String::from_utf8(
                    name.iter()
                        .map(u8::to_ascii_lowercase)
                        .collect(),
                )
                .map_err(|_| {
                    "response-observation v2 header name is not ASCII"
                        .to_string()
                })?,
            )
            .or_default()
            .push(value.to_vec());
    }
    Ok((
        status,
        headers,
        after_head,
        u64::try_from(head_length).map_err(|_| {
            "response-observation v2 head length overflows u64"
                .to_string()
        })?,
    ))
}

fn response_observation_v2_csv_tokens(
    values: Option<&Vec<Vec<u8>>>,
    field: &str,
) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for value in values.into_iter().flatten() {
        let value = std::str::from_utf8(value).map_err(|_| {
            format!(
                "response-observation v2 {field} is not ASCII"
            )
        })?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty()
                || !token.as_bytes().iter().copied().all(
                    is_http_token_byte,
                )
            {
                return Err(format!(
                    "response-observation v2 {field} token is invalid"
                ));
            }
            result.push(token.to_ascii_lowercase());
        }
    }
    Ok(result)
}

fn response_observation_v2_content_length(
    values: Option<&Vec<Vec<u8>>>,
) -> Result<Option<u64>, String> {
    let mut observed = None;
    for value in values.into_iter().flatten() {
        let value = std::str::from_utf8(value).map_err(|_| {
            "response-observation v2 Content-Length is not ASCII"
                .to_string()
        })?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty()
                || !item.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(
                    "response-observation v2 Content-Length is invalid"
                        .to_string(),
                );
            }
            let parsed = item.parse::<u64>().map_err(|_| {
                "response-observation v2 Content-Length overflows"
                    .to_string()
            })?;
            if observed.is_some_and(|current| current != parsed) {
                return Err(
                    "response-observation v2 has conflicting Content-Length values"
                        .to_string(),
                );
            }
            observed = Some(parsed);
        }
    }
    Ok(observed)
}

fn response_observation_v2_parse_chunked(
    bytes: &[u8],
    declared_trailers: &[String],
) -> Result<
    (Zeroizing<Vec<u8>>, usize, u64, Vec<String>),
    String,
> {
    let mut cursor = 0usize;
    let mut chunks = 0usize;
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let line_end = bytes
            .get(cursor..)
            .ok_or("response-observation v2 chunk cursor is invalid")?
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("response-observation v2 chunk line is incomplete")?;
        let line = &bytes[cursor..cursor + line_end];
        if line.is_empty()
            || line.len() > 8192
            || line.contains(&b';')
            || !line.iter().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(
                "response-observation v2 chunk size is invalid or uses unsupported extensions"
                    .to_string(),
            );
        }
        let size = u64::from_str_radix(
            std::str::from_utf8(line).map_err(|_| {
                "response-observation v2 chunk size is not ASCII"
                    .to_string()
            })?,
            16,
        )
        .map_err(|_| {
            "response-observation v2 chunk size overflows".to_string()
        })?;
        cursor = cursor
            .checked_add(line_end + 2)
            .ok_or("response-observation v2 chunk cursor overflow")?;
        if size == 0 {
            break;
        }
        chunks = chunks.saturating_add(1);
        if chunks > MAX_V2_CHUNKS
            || size > RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES
        {
            return Err(
                "response-observation v2 chunk count or size exceeds its bound"
                    .to_string(),
            );
        }
        let size = usize::try_from(size).map_err(|_| {
            "response-observation v2 chunk size exceeds the platform"
                .to_string()
        })?;
        let end = cursor
            .checked_add(size)
            .ok_or("response-observation v2 chunk length overflow")?;
        if end + 2 > bytes.len()
            || &bytes[end..end + 2] != b"\r\n"
            || body.len().saturating_add(size)
                > RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES as usize
        {
            return Err(
                "response-observation v2 chunk is truncated or exceeds the entity bound"
                    .to_string(),
            );
        }
        body.extend_from_slice(&bytes[cursor..end]);
        cursor = end + 2;
    }
    let mut observed_trailers = Vec::new();
    let remaining = bytes
        .get(cursor..)
        .ok_or("response-observation v2 trailer cursor is invalid")?;
    let (trailer_bytes, trailer_consumed) =
        if remaining.starts_with(b"\r\n") {
            (&remaining[..0], 2usize)
        } else {
            let trailer_end = remaining
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .ok_or(
                    "response-observation v2 trailer block is incomplete",
                )?;
            if trailer_end.saturating_add(4)
                > MAX_V2_HTTP_HEAD_BYTES
            {
                return Err(
                    "response-observation v2 trailer block exceeds its bound"
                        .to_string(),
                );
            }
            (&remaining[..trailer_end + 2], trailer_end + 4)
        };
    if !trailer_bytes.is_empty() {
        let mut trailer_count = 0usize;
        for raw in trailer_bytes.split(|byte| *byte == b'\n') {
            let line = raw
                .strip_suffix(b"\r")
                .ok_or(
                    "response-observation v2 trailer requires CRLF",
                )?;
            if line.is_empty() {
                continue;
            }
            trailer_count = trailer_count.saturating_add(1);
            if trailer_count > MAX_V2_HTTP_HEADERS {
                return Err(
                    "response-observation v2 trailer count exceeds its bound"
                        .to_string(),
                );
            }
            let colon = line.iter().position(|byte| *byte == b':')
                .ok_or("response-observation v2 trailer lacks a colon")?;
            let name = &line[..colon];
            if name.is_empty()
                || !name.iter().copied().all(is_http_token_byte)
            {
                return Err(
                    "response-observation v2 trailer name is invalid"
                        .to_string(),
                );
            }
            let name = String::from_utf8(
                name.iter()
                    .map(u8::to_ascii_lowercase)
                    .collect(),
            )
            .map_err(|_| {
                "response-observation v2 trailer name is not ASCII"
                    .to_string()
            })?;
            if matches!(
                name.as_str(),
                "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "host"
                    | "trailer"
            ) || !declared_trailers.contains(&name)
                || line[colon + 1..].iter().any(|byte| {
                    *byte == 0
                        || *byte == b'\r'
                        || *byte == b'\n'
                        || (*byte < 0x20 && *byte != b'\t')
                        || *byte == 0x7f
                })
            {
                return Err(
                    "response-observation v2 trailer is forbidden, undeclared, or invalid"
                        .to_string(),
                );
            }
            observed_trailers.push(name);
        }
    }
    if observed_trailers.len() != declared_trailers.len()
        || declared_trailers.iter().any(|declared| {
            observed_trailers
                .iter()
                .filter(|observed| *observed == declared)
                .count()
                != 1
        })
    {
        return Err(
            "response-observation v2 trailer declaration does not exactly match the trailer block"
                .to_string(),
        );
    }
    cursor = cursor
        .checked_add(trailer_consumed)
        .ok_or("response-observation v2 trailer cursor overflow")?;
    observed_trailers.sort();
    Ok((
        body,
        cursor,
        u64::try_from(trailer_consumed).map_err(|_| {
            "response-observation v2 trailer length overflows"
                .to_string()
        })?,
        observed_trailers,
    ))
}

fn http11_sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn http11_canonical_json_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::to_value(value)?)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn http11_is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

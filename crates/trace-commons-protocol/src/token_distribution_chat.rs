//! Bounded, read-only extraction from a complete Chat Completions response.
//! Caller verifies the original bytes with the provider before asserting provenance.
//! Responses, tools, reasoning, and partial streams are deliberately unavailable.
use crate::token_distribution::*;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChatCaptureError {
    #[error("token-capture-unavailable")]
    Unavailable,
    #[error("token-capture-malformed")]
    Malformed,
    #[error("token-capture-limit")]
    Limit,
    #[error("token-capture-incomplete")]
    Incomplete,
}

/// Content-bearing extraction results intentionally do not implement Debug.
pub struct ChatTokenSegment {
    pub reported_model: Option<String>,
    pub choice: u32,
    pub text: Vec<u8>,
    pub records: Vec<TokenRecord>,
}

#[derive(Default)]
struct Builder {
    text: Vec<u8>,
    records: Vec<TokenRecord>,
    token_end: u64,
    finished: bool,
    unavailable: bool,
}

fn number(value: &Value) -> Result<LogProbability, ChatCaptureError> {
    let n = value.as_f64().ok_or(ChatCaptureError::Malformed)?;
    if !n.is_finite() || n > 0.0 {
        return Err(ChatCaptureError::Malformed);
    }
    // OpenAI-compatible APIs use -9999 for unavailable probability. It must
    // never enter averages as if it were an ordinary measured log probability.
    Ok(if n == -9999.0 {
        LogProbability::Unavailable
    } else {
        LogProbability::Finite(n)
    })
}
fn token(value: &Value) -> Result<TokenValue, ChatCaptureError> {
    let bytes = match value.get("bytes") {
        Some(Value::Array(values)) => {
            if values.is_empty() || values.len() > 65536 {
                return Err(ChatCaptureError::Limit);
            }
            values
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or(ChatCaptureError::Malformed)
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        None | Some(Value::Null) => value
            .get("token")
            .and_then(Value::as_str)
            .ok_or(ChatCaptureError::Malformed)?
            .as_bytes()
            .to_vec(),
        _ => return Err(ChatCaptureError::Malformed),
    };
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(ChatCaptureError::Limit);
    }
    Ok(TokenValue {
        bytes,
        token_id: None,
        logprob: number(value.get("logprob").ok_or(ChatCaptureError::Malformed)?)?,
    })
}

impl Builder {
    fn push(&mut self, choice: &Value, streaming: bool) -> Result<(), ChatCaptureError> {
        if self.finished {
            return Err(ChatCaptureError::Malformed);
        }
        let message = choice
            .get(if streaming { "delta" } else { "message" })
            .ok_or(ChatCaptureError::Malformed)?;
        if !message.is_object() {
            return Err(ChatCaptureError::Malformed);
        }
        if [
            "tool_calls",
            "function_call",
            "reasoning",
            "reasoning_content",
            "refusal",
        ]
        .iter()
        .any(|key| message.get(key).is_some_and(|v| !v.is_null()))
        {
            self.unavailable = true;
        }
        if let Some(content) = message.get("content").filter(|v| !v.is_null()) {
            let text = content.as_str().ok_or(ChatCaptureError::Malformed)?;
            if self.text.len().saturating_add(text.len()) > MAX_ATTACHMENT_BYTES {
                return Err(ChatCaptureError::Limit);
            }
            self.text.extend_from_slice(text.as_bytes());
        }
        if let Some(entries) = choice
            .get("logprobs")
            .and_then(|v| v.get("content"))
            .filter(|v| !v.is_null())
        {
            let entries = entries.as_array().ok_or(ChatCaptureError::Malformed)?;
            if self.records.len().saturating_add(entries.len()) > 131072 {
                return Err(ChatCaptureError::Limit);
            }
            for entry in entries {
                let chosen = token(entry)?;
                let values = entry
                    .get("top_logprobs")
                    .filter(|v| !v.is_null())
                    .map(|v| v.as_array().ok_or(ChatCaptureError::Malformed))
                    .transpose()?;
                let returned = values.map_or(0, Vec::len);
                // Bound even omitted alternatives. Oversized provider responses
                // are unavailable rather than silently treated as complete.
                if returned > 4096 {
                    return Err(ChatCaptureError::Limit);
                }
                let alternatives = values
                    .into_iter()
                    .flatten()
                    .take(MAX_ALTERNATIVES)
                    .map(token)
                    .collect::<Result<Vec<_>, _>>()?;
                let end = self
                    .token_end
                    .checked_add(chosen.bytes.len() as u64)
                    .ok_or(ChatCaptureError::Limit)?;
                self.records.push(TokenRecord {
                    index: self.records.len() as u64,
                    span: ByteSpan {
                        start: self.token_end,
                        end,
                    },
                    chosen,
                    alternatives,
                    returned_alternatives: returned as u32,
                });
                self.token_end = end;
            }
        }
        if let Some(reason) = choice.get("finish_reason").filter(|v| !v.is_null()) {
            let reason = reason.as_str().ok_or(ChatCaptureError::Malformed)?;
            if reason != "stop" {
                self.unavailable = true;
            }
            self.finished = true;
        }
        Ok(())
    }
    fn finish(
        self,
        choice: u32,
        reported_model: Option<String>,
    ) -> Result<ChatTokenSegment, ChatCaptureError> {
        if !self.finished {
            return Err(ChatCaptureError::Incomplete);
        }
        if self.unavailable || self.records.is_empty() {
            return Err(ChatCaptureError::Unavailable);
        }
        if self.token_end != self.text.len() as u64 {
            return Err(ChatCaptureError::Malformed);
        }
        for record in &self.records {
            if self.text[record.span.start as usize..record.span.end as usize]
                != record.chosen.bytes
            {
                return Err(ChatCaptureError::Malformed);
            }
        }
        Ok(ChatTokenSegment {
            reported_model,
            choice,
            text: self.text,
            records: self.records,
        })
    }
}

/// `streaming` is selected from the authenticated exchange's actual protocol,
/// not guessed from body contents. Original wire bytes are never modified.
pub fn extract_chat_tokens(
    bytes: &[u8],
    streaming: bool,
) -> Result<Vec<ChatTokenSegment>, ChatCaptureError> {
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(ChatCaptureError::Limit);
    }
    let mut builders: BTreeMap<u32, Builder> = BTreeMap::new();
    let mut response_id = None;
    let mut reported_model: Option<String> = None;
    let mut frame = |value: Value| -> Result<(), ChatCaptureError> {
        if value.get("error").is_some() {
            return Err(ChatCaptureError::Unavailable);
        }
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            if model.len() > 256 || reported_model.as_deref().is_some_and(|old| old != model) {
                return Err(ChatCaptureError::Malformed);
            }
            reported_model = Some(model.to_owned());
        }
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ChatCaptureError::Malformed)?;
        if id.len() > 256 {
            return Err(ChatCaptureError::Limit);
        }
        if response_id
            .as_deref()
            .is_some_and(|previous| previous != id)
        {
            return Err(ChatCaptureError::Malformed);
        }
        response_id = Some(id.to_owned());
        let choices = value
            .get("choices")
            .and_then(Value::as_array)
            .ok_or(ChatCaptureError::Malformed)?;
        let mut seen = std::collections::BTreeSet::new();
        for choice in choices {
            let index = choice
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(ChatCaptureError::Malformed)?;
            if !seen.insert(index) {
                return Err(ChatCaptureError::Malformed);
            }
            if !builders.contains_key(&index) && builders.len() >= 16 {
                return Err(ChatCaptureError::Limit);
            }
            builders.entry(index).or_default().push(choice, streaming)?;
        }
        Ok(())
    };
    if streaming {
        let text = std::str::from_utf8(bytes).map_err(|_| ChatCaptureError::Malformed)?;
        let mut data = String::new();
        let mut done = false;
        for line in text.split_terminator('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                if data.is_empty() {
                    continue;
                }
                if done {
                    return Err(ChatCaptureError::Malformed);
                }
                if data == "[DONE]" {
                    done = true;
                } else {
                    frame(serde_json::from_str(&data).map_err(|_| ChatCaptureError::Malformed)?)?;
                }
                data.clear();
            } else if let Some(value) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value.strip_prefix(' ').unwrap_or(value));
            } else if !line.starts_with(':') {
                // Unknown event framing is not silently combined into a signed
                // response we claim to understand (including retry/id frames).
                return Err(ChatCaptureError::Unavailable);
            }
        }
        if !done || !data.is_empty() {
            return Err(ChatCaptureError::Incomplete);
        }
    } else {
        frame(serde_json::from_slice(bytes).map_err(|_| ChatCaptureError::Malformed)?)?;
    }
    if builders.is_empty() {
        return Err(ChatCaptureError::Unavailable);
    }
    builders
        .into_iter()
        .map(|(choice, builder)| builder.finish(choice, reported_model.clone()))
        .collect()
}

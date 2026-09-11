use serde_json::{Value, json};
use trace_commons_protocol::token_distribution::LogProbability;
use trace_commons_protocol::token_distribution_chat::*;

fn choice(text: &str, finish: Value) -> Value {
    json!({"index":0,"delta":{"content":text},"finish_reason":finish,"logprobs":{"content":[{"token":text,"logprob":-0.7,"top_logprobs":[{"token":"other","logprob":-2.3}]}]}})
}
fn event(choice: Value) -> String {
    format!("data: {}\n\n", json!({"id":"c1","choices":[choice]}))
}
fn buffered() -> Vec<u8> {
    let mut c = choice("hello", json!("stop"));
    c["message"] = c.as_object_mut().unwrap().remove("delta").unwrap();
    serde_json::to_vec(&json!({"id":"c1","choices":[c]})).unwrap()
}
#[test]
fn buffered_and_streaming_preserve_provider_values() {
    let output = extract_chat_tokens(&buffered(), false).unwrap();
    assert_eq!(output[0].text, b"hello");
    assert!(matches!(
        output[0].records[0].chosen.logprob,
        LogProbability::Finite(-0.7)
    ));
    let stream = event(choice("hel", Value::Null))
        + &event(choice("lo", json!("stop")))
        + "data: [DONE]\n\n";
    let output = extract_chat_tokens(stream.as_bytes(), true).unwrap();
    assert_eq!(output[0].text, b"hello");
    assert_eq!(output[0].records[1].span.start, 3);
}
#[test]
fn final_frame_probabilities_are_not_lost() {
    let mut first = choice("hello", Value::Null);
    first["logprobs"] = Value::Null;
    let mut last = choice("hello", json!("stop"));
    last["delta"] = json!({});
    let stream = event(first) + &event(last) + "data: [DONE]\n\n";
    let output = extract_chat_tokens(stream.as_bytes(), true).unwrap();
    assert_eq!(output[0].records.len(), 1);
    assert_eq!(output[0].records[0].chosen.bytes, b"hello");
}
#[test]
fn missing_completion_and_repeated_finish_frames_fail_closed() {
    let stream = event(choice("hello", json!("stop")));
    assert!(matches!(
        extract_chat_tokens(stream.as_bytes(), true),
        Err(ChatCaptureError::Incomplete)
    ));
    let duplicate = stream.clone() + &stream + "data: [DONE]\n\n";
    assert!(matches!(
        extract_chat_tokens(duplicate.as_bytes(), true),
        Err(ChatCaptureError::Malformed)
    ));
}
#[test]
fn changed_response_identity_cannot_be_stitched_into_one_capture() {
    let stream = event(choice("a", Value::Null))
        + &event(choice("b", json!("stop"))).replace("c1", "c2")
        + "data: [DONE]\n\n";
    assert!(matches!(
        extract_chat_tokens(stream.as_bytes(), true),
        Err(ChatCaptureError::Malformed)
    ));
}
#[test]
fn absent_logprobs_and_tool_output_are_unavailable() {
    let mut body: Value = serde_json::from_slice(&buffered()).unwrap();
    body["choices"][0]["logprobs"] = Value::Null;
    assert!(matches!(
        extract_chat_tokens(&serde_json::to_vec(&body).unwrap(), false),
        Err(ChatCaptureError::Unavailable)
    ));
    body = serde_json::from_slice(&buffered()).unwrap();
    body["choices"][0]["message"]["tool_calls"] = json!([{"id":"tool"}]);
    assert!(matches!(
        extract_chat_tokens(&serde_json::to_vec(&body).unwrap(), false),
        Err(ChatCaptureError::Unavailable)
    ));
}
#[test]
fn wire_bytes_override_lossy_token_labels_and_must_reconstruct_text() {
    let mut body: Value = serde_json::from_slice(&buffered()).unwrap();
    body["choices"][0]["message"]["content"] = "é".into();
    body["choices"][0]["logprobs"]["content"] = json!([
        {"token":"�","bytes":[195],"logprob":-1.0},
        {"token":"�","bytes":[169],"logprob":-1.0}
    ]);
    let result = extract_chat_tokens(&serde_json::to_vec(&body).unwrap(), false).unwrap();
    assert_eq!(result[0].records.len(), 2);
    body["choices"][0]["logprobs"]["content"][1]["bytes"] = json!([168]);
    assert!(matches!(
        extract_chat_tokens(&serde_json::to_vec(&body).unwrap(), false),
        Err(ChatCaptureError::Malformed)
    ));
}
#[test]
fn unavailable_sentinel_is_not_a_measured_probability() {
    let mut body: Value = serde_json::from_slice(&buffered()).unwrap();
    body["choices"][0]["logprobs"]["content"][0]["logprob"] = json!(-9999.0);
    let output = extract_chat_tokens(&serde_json::to_vec(&body).unwrap(), false).unwrap();
    assert!(matches!(
        output[0].records[0].chosen.logprob,
        LogProbability::Unavailable
    ));
}
#[test]
fn crlf_and_usage_only_frames_are_supported() {
    let stream = (event(choice("hello", json!("stop")))
        + "data: {\"id\":\"c1\",\"choices\":[],\"usage\":{}}\n\ndata: [DONE]\n\n")
        .replace('\n', "\r\n");
    assert!(extract_chat_tokens(stream.as_bytes(), true).is_ok());
}

#[test]
fn a_single_final_newline_does_not_complete_an_sse_event() {
    let stream = event(choice("hello", json!("stop"))) + "data: [DONE]\n";
    assert!(matches!(
        extract_chat_tokens(stream.as_bytes(), true),
        Err(ChatCaptureError::Incomplete)
    ));
}

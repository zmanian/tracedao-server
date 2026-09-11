//! Private redaction provenance. Never serialized into a contribution.
use crate::token_distribution::{ByteSpan, RedactionEdit};

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateRedactionEdits(pub Vec<RedactionEdit>);
impl std::fmt::Debug for PrivateRedactionEdits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<private redaction map>")
    }
}

/// Byte origins are carried through actual replacement operations. A missing
/// origin denotes inserted text, including a replacement edited again later.
/// Bounds keep provenance work independent of unbounded classifier output.
pub(crate) struct EditMap {
    original_len: usize,
    origins: Vec<u32>,
}
impl EditMap {
    pub(crate) fn new(len: usize) -> Option<Self> {
        (len <= 1024 * 1024).then(|| Self {
            original_len: len,
            origins: (0..len as u32).collect(),
        })
    }
    pub(crate) fn apply(&mut self, edits: &[RedactionEdit]) -> Option<()> {
        let mut output = Vec::new();
        let mut cursor = 0;
        for edit in edits {
            let start = usize::try_from(edit.original.start).ok()?;
            let end = usize::try_from(edit.original.end).ok()?;
            if start < cursor || end < start || end > self.origins.len() {
                return None;
            }
            if output
                .len()
                .saturating_add(start - cursor)
                .saturating_add(edit.replacement.len())
                > 1024 * 1024
            {
                return None;
            }
            output.extend_from_slice(&self.origins[cursor..start]);
            output.resize(output.len() + edit.replacement.len(), u32::MAX);
            cursor = end;
        }
        if output.len().saturating_add(self.origins.len() - cursor) > 1024 * 1024 {
            return None;
        }
        output.extend_from_slice(&self.origins[cursor..]);
        self.origins = output;
        Some(())
    }
    pub(crate) fn finish(self, sanitized: &[u8]) -> Option<PrivateRedactionEdits> {
        if self.origins.len() != sanitized.len() {
            return None;
        }
        let mut result = Vec::new();
        let mut original = 0usize;
        let mut inserted = Vec::new();
        for (byte, origin) in sanitized.iter().zip(self.origins) {
            if origin == u32::MAX {
                inserted.push(*byte);
                continue;
            }
            let origin = origin as usize;
            if origin < original {
                return None;
            }
            if origin > original || !inserted.is_empty() {
                result.push(RedactionEdit {
                    original: ByteSpan {
                        start: original as u64,
                        end: origin as u64,
                    },
                    replacement: std::mem::take(&mut inserted),
                });
            }
            original = origin + 1;
        }
        if original < self.original_len || !inserted.is_empty() {
            result.push(RedactionEdit {
                original: ByteSpan {
                    start: original as u64,
                    end: self.original_len as u64,
                },
                replacement: inserted,
            });
        }
        (result.len() <= 4096).then_some(PrivateRedactionEdits(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn edit(start: u64, end: u64, text: &str) -> RedactionEdit {
        RedactionEdit {
            original: ByteSpan { start, end },
            replacement: text.as_bytes().to_vec(),
        }
    }
    #[test]
    fn repeated_text_and_edits_inside_placeholders_compose_without_matching() {
        let mut map = EditMap::new(11).unwrap(); // aa secret aa
        map.apply(&[edit(3, 9, "<name>")]).unwrap();
        map.apply(&[edit(4, 8, "hidden")]).unwrap();
        let edits = map.finish(b"aa <hidden>aa").unwrap();
        assert_eq!(edits.0.len(), 1);
        assert_eq!(edits.0[0].original, ByteSpan { start: 3, end: 9 });
        assert_eq!(edits.0[0].replacement, b"<hidden>");
        assert_eq!(format!("{edits:?}"), "<private redaction map>");
    }
    #[cfg(any(
        feature = "near-ai-privacy-filter",
        feature = "self-hosted-privacy-filter"
    ))]
    #[tokio::test]
    async fn actual_secret_and_codepoint_classifier_edits_keep_unchanged_unicode() {
        use crate::trace_contribution::*;
        struct Names;
        #[async_trait::async_trait]
        impl PrivacyFilterAdapter for Names {
            async fn redact_text(
                &self,
                text: &str,
            ) -> Result<Option<SafePrivacyFilterRedaction>, TraceContributionError> {
                let spans = text
                    .match_indices("Alice")
                    .map(|(offset, _)| crate::privacy_filter_spans::ClassifySpan {
                        category: "person_name".into(),
                        start: text[..offset].chars().count(),
                        end: text[..offset + 5].chars().count(),
                        score: 1.0,
                    })
                    .collect::<Vec<_>>();
                crate::privacy_filter_spans::apply_spans("test", text, &spans)
            }
        }
        let redactor = DeterministicTraceRedactor::deterministic_only(Vec::new())
            .with_privacy_filter(std::sync::Arc::new(Names), PrivacyFilterBackendTag::NearAi);
        let input = "é Alice /Users/alice/private.txt and Alice done";
        let (filtered, edits) = redactor.redact_text_with_edits(input).await.unwrap();
        let edits = edits.unwrap();
        let mut rebuilt = Vec::new();
        let mut cursor = 0;
        for edit in &edits.0 {
            rebuilt.extend_from_slice(&input.as_bytes()[cursor..edit.original.start as usize]);
            rebuilt.extend_from_slice(&edit.replacement);
            cursor = edit.original.end as usize;
        }
        rebuilt.extend_from_slice(&input.as_bytes()[cursor..]);
        assert_eq!(rebuilt, filtered.redacted.as_bytes());
        assert_eq!(edits.0.len(), 3);
        assert_eq!(
            &input.as_bytes()[edits.0[0].original.start as usize..edits.0[0].original.end as usize],
            b"Alice"
        );
        assert!(filtered.redacted.starts_with("é "));
        assert!(filtered.redacted.ends_with(" done"));
        assert!(
            !serde_json::to_string(
                &crate::privacy_filter_spans::apply_spans(
                    "test",
                    "Alice",
                    &[crate::privacy_filter_spans::ClassifySpan {
                        category: "person_name".into(),
                        start: 0,
                        end: 5,
                        score: 1.0
                    }]
                )
                .unwrap()
            )
            .unwrap()
            .contains("private_edits")
        );
    }
}

//! Quote-aware statement framing shared by the schema and read compilers.
pub(super) fn reviewed_schema_statement_count(sql: &str) -> Option<u64> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum LexState {
        Normal,
        SingleQuote,
        DoubleQuote,
        Backtick,
        Bracket,
        LineComment,
        BlockComment,
    }

    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut state = LexState::Normal;
    let mut statement_has_token = false;
    let mut count = 0_u64;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            LexState::Normal => match (byte, next) {
                (b'-', Some(b'-')) => {
                    state = LexState::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = LexState::BlockComment;
                    index += 1;
                }
                (b'\'', _) => {
                    statement_has_token = true;
                    state = LexState::SingleQuote;
                }
                (b'"', _) => {
                    statement_has_token = true;
                    state = LexState::DoubleQuote;
                }
                (b'`', _) => {
                    statement_has_token = true;
                    state = LexState::Backtick;
                }
                (b'[', _) => {
                    statement_has_token = true;
                    state = LexState::Bracket;
                }
                (b';', _) if statement_has_token => {
                    count = count.checked_add(1)?;
                    statement_has_token = false;
                }
                _ if !byte.is_ascii_whitespace() => statement_has_token = true,
                _ => {}
            },
            LexState::SingleQuote if byte == b'\'' => {
                if next == Some(b'\'') {
                    index += 1;
                } else {
                    state = LexState::Normal;
                }
            }
            LexState::DoubleQuote if byte == b'"' => {
                if next == Some(b'"') {
                    index += 1;
                } else {
                    state = LexState::Normal;
                }
            }
            LexState::Backtick if byte == b'`' => {
                if next == Some(b'`') {
                    index += 1;
                } else {
                    state = LexState::Normal;
                }
            }
            LexState::Bracket if byte == b']' => state = LexState::Normal,
            LexState::LineComment if matches!(byte, b'\n' | b'\r') => state = LexState::Normal,
            LexState::BlockComment if byte == b'*' && next == Some(b'/') => {
                state = LexState::Normal;
                index += 1;
            }
            _ => {}
        }
        index += 1;
    }
    if !matches!(state, LexState::Normal | LexState::LineComment) {
        return None;
    }
    if statement_has_token {
        count = count.checked_add(1)?;
    }
    Some(count)
}

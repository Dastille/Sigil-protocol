//! Stored names made safe to print.
//!
//! Member names, file names and paths inside an archive come from whoever made it (or
//! from damage). Printed raw, a name with control characters could move the cursor,
//! recolour or clear the terminal, or fake extra lines of output. Every place that prints
//! a stored name passes it through [`name`]; whole messages printed by the CLI pass
//! through [`line`] as a second layer.

/// Characters that change how text is laid out without being visible: the C0/C1
/// controls and DEL, plus the Unicode direction and zero-width format characters.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn escape_into(out: &mut String, c: char) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
    }
}

/// A stored name for display: every control or invisible layout character is shown as
/// an escape (`\n`, `\u{1b}`), so the name prints as one plain line.
pub fn name(s: &str) -> String {
    if !s.chars().any(hidden) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if hidden(c) {
            escape_into(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

/// A whole message for display: like [`name`], but line breaks and tabs are kept.
pub fn line(s: &str) -> String {
    if !s.chars().any(|c| hidden(c) && c != '\n' && c != '\t') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if hidden(c) && c != '\n' && c != '\t' {
            escape_into(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_controls_and_invisible_layout_characters() {
        assert_eq!(name("plain/name.txt"), "plain/name.txt");
        assert_eq!(name("a\u{1b}[31mRED\u{1b}[0m"), "a\\u{1b}[31mRED\\u{1b}[0m");
        assert_eq!(name("two\nlines\r\t"), "two\\nlines\\r\\t");
        assert_eq!(name("x\u{202E}gnp.exe"), "x\\u{202e}gnp.exe");
        assert_eq!(name("del\u{7f}c1\u{9b}"), "del\\u{7f}c1\\u{9b}");
        assert_eq!(name("caf\u{e9} \u{1F600}"), "caf\u{e9} \u{1F600}");
        assert_eq!(line("a\nb\tc\u{1b}]0;t\u{7}"), "a\nb\tc\\u{1b}]0;t\\u{7}");
    }
}

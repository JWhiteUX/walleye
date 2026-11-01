//! Characters that render invisibly or reorder text. One table for every
//! place capture strings become text: ingest (SSIDs), the Markdown report
//! (walleye-case `sanitize`) and, mirrored in TypeScript, the UI's
//! `visible()` (app/src/shared/format.ts). Keep the three in sync.

/// Cf (format), Zl, Zp, the whole tag block, Hangul fillers, the Braille
/// blank, the combining grapheme joiner, variation selectors and Mongolian
/// free variation selectors. Cc is checked separately (`char::is_control`).
/// Table from Unicode 15.1, no dependency.
#[rustfmt::skip]
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        // Cf
        '\u{00ad}' | '\u{0600}'..='\u{0605}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' |
        '\u{0890}'..='\u{0891}' | '\u{08e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' |
        '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' |
        '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' |
        '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' |
        // Tag characters (incl. the Cf ones) and unassigned rest of the block.
        '\u{e0000}'..='\u{e007f}' |
        // Zl, Zp
        '\u{2028}' | '\u{2029}' |
        // Hangul fillers, Braille blank
        '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}' | '\u{2800}' |
        // Combining grapheme joiner, variation selectors, Mongolian FVS
        '\u{034f}' | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}' |
        '\u{180b}'..='\u{180d}' | '\u{180f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_review_cases() {
        for c in [
            '\u{e0041}',
            '\u{3164}',
            '\u{034f}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{180b}',
            '\u{202e}',
            '\u{2029}',
            '\u{2800}',
        ] {
            assert!(is_invisible(c), "{:x}", c as u32);
        }
        for c in ['a', 'é', '😀', ' ', '"'] {
            assert!(!is_invisible(c), "{c}");
        }
    }
}

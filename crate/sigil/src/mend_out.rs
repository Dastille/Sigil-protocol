//! Where plain `sigil mend` writes when `-o` is left out, and how hints spell a
//! copyable `sigil mend` command.
//!
//! The default output sits next to the input as `<stem>.mended.<ext>` (for example
//! `photos.sg1` → `photos.mended.sg1`; a folder or a file with no extension gets
//! `<name>.mended`). If that name is taken, `-2`, `-3`, … is added before the extension
//! (`photos.mended-2.sg1`). The input itself and any existing file are never chosen.

use std::path::{Path, PathBuf};

/// Highest numbered suffix tried before giving up (`<stem>.mended-999.<ext>`).
const MAX_TRIES: u32 = 999;

/// Pick a path next to `input` for a mended copy that does not exist yet.
///
/// Never returns `input` itself and never returns a path that already exists (checked
/// with `symlink_metadata`, so a dangling symlink also counts as taken). Errors when
/// the input has no file name or every numbered name up to 999 is taken.
pub fn default_mend_output(input: &Path) -> crate::Result<PathBuf> {
    let name = input
        .file_name()
        .ok_or_else(|| {
            crate::Error::Msg(format!(
                "cannot pick an output name for {}; give one with -o, for example: sigil mend {} -o fixed.sg1",
                input.display(),
                shell_word(&input.display().to_string())
            ))
        })?
        .to_string_lossy()
        .into_owned();
    let is_dir = input.is_dir();
    // Split "name.ext" (a leading dot is part of the stem, not an extension).
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && !is_dir => (name[..i].to_string(), Some(name[i + 1..].to_string())),
        _ => (name.clone(), None),
    };
    let parent = input.parent().unwrap_or_else(|| Path::new(""));
    for n in 1..=MAX_TRIES {
        let tag = if n == 1 {
            "mended".to_string()
        } else {
            format!("mended-{n}")
        };
        let file = match &ext {
            Some(e) => format!("{stem}.{tag}.{e}"),
            None => format!("{stem}.{tag}"),
        };
        let cand = parent.join(file);
        if cand.as_path() != input && std::fs::symlink_metadata(&cand).is_err() {
            return Ok(cand);
        }
    }
    Err(crate::Error::Msg(format!(
        "every default output name next to {} is taken (up to .mended-{MAX_TRIES}); choose one with -o",
        input.display()
    )))
}

/// Quote one word for a POSIX shell so it can be pasted as-is (`it's` → `'it'\''s'`).
/// Plain words made only of safe characters are returned unchanged.
pub fn shell_word(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:,@%=".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The full, copyable repair command for `input`: `sigil mend <input>` (quoted when
/// needed). Plain `sigil mend` tries the quick repair, then the deeper one, and picks a
/// safe output name next to the input.
pub fn mend_command(input: &Path) -> String {
    format!("sigil mend {}", shell_word(&input.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> crate::staging::TempDir {
        crate::staging::TempDir::create(tag).expect("scratch folder")
    }

    #[test]
    fn default_name_scheme_and_no_clobber() {
        let t = tmpdir("mend-out-name");
        let d = t.path();
        let input = d.join("photos.sg1");
        std::fs::write(&input, b"x").expect("write");
        let a = default_mend_output(&input).expect("a");
        assert_eq!(a, d.join("photos.mended.sg1"));
        assert_ne!(a, input);
        std::fs::write(&a, b"taken").expect("write");
        let b = default_mend_output(&input).expect("b");
        assert_eq!(b, d.join("photos.mended-2.sg1"));
        // A mended file mended again gets its own name, never itself.
        let again = default_mend_output(&a).expect("again");
        assert_ne!(again, a);
        assert_eq!(again, d.join("photos.mended.mended.sg1"));
    }

    #[test]
    fn default_name_no_ext_dotfile_and_folder() {
        let t = tmpdir("mend-out-ext");
        let d = t.path();
        assert_eq!(
            default_mend_output(&d.join("blob")).expect("blob"),
            d.join("blob.mended")
        );
        assert_eq!(
            default_mend_output(&d.join(".hidden")).expect("dot"),
            d.join(".hidden.mended")
        );
        let folder = d.join("album.v1");
        std::fs::create_dir_all(&folder).expect("mkdir");
        assert_eq!(
            default_mend_output(&folder).expect("dir"),
            d.join("album.v1.mended")
        );
        assert!(default_mend_output(Path::new("/")).is_err());
    }

    #[test]
    fn shell_words_paste_safely() {
        assert_eq!(shell_word("a/b.sg1"), "a/b.sg1");
        assert_eq!(shell_word("my file.sg1"), "'my file.sg1'");
        assert_eq!(shell_word("it's.sg1"), r"'it'\''s.sg1'");
        assert_eq!(shell_word(""), "''");
        assert_eq!(mend_command(Path::new("x y.sg1")), "sigil mend 'x y.sg1'");
    }
}

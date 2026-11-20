//! What a decrypted file can be shown as. Decisions only; decoding happens in the UI, in memory.

/// Larger files are not decrypted for a preview.
pub const MAX_PREVIEW: u64 = 200 * 1024 * 1024;
/// Text previews show at most this much.
pub const MAX_TEXT: usize = 1024 * 1024;
/// Thumbnails only for images up to this size.
pub const MAX_THUMB: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guess {
    Image,
    Text,
    /// Extension unknown: decrypt and sniff.
    Unknown,
    /// Known binary type we can't show (archive, video, office file...).
    Other,
}

fn ext(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

const IMAGE: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "ico", "svg", "avif", "heic", "heif", "tga", "xpm", "pnm", "ppm", "pgm"];
const TEXT: &[&str] = &[
    "txt", "md", "markdown", "rst", "log", "csv", "tsv", "json", "jsonl", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "html", "htm", "css", "js", "ts", "tsx", "jsx", "rs", "py",
    "rb", "go", "c", "h", "cc", "cpp", "hpp", "java", "kt", "swift", "m", "sh", "bash", "zsh", "fish", "ps1", "sql", "tex", "bib", "srt", "vtt", "env", "gitignore", "diff", "patch",
    "pem", "asc", "gpg", "eml", "vcf", "ics", "plist", "lua", "pl", "php", "r", "scala", "zig", "nix", "mk", "cmake", "dockerfile", "org",
];

pub fn guess(name: &str) -> Guess {
    let e = ext(name);
    if e.is_empty() {
        return Guess::Unknown;
    }
    if IMAGE.contains(&e.as_str()) {
        Guess::Image
    } else if TEXT.contains(&e.as_str()) {
        Guess::Text
    } else {
        // Common binary formats: no point decrypting them for a preview.
        const BIN: &[&str] = &["zip", "gz", "tgz", "xz", "bz2", "zst", "7z", "rar", "tar", "iso", "dmg", "img", "mp4", "mov", "mkv", "avi", "webm", "mp3", "m4a", "flac", "wav", "ogg", "opus", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "exe", "dll", "so", "dylib", "bin", "deb", "rpm", "apk", "ipa", "sqlite", "db", "kdbx"];
        if BIN.contains(&e.as_str()) { Guess::Other } else { Guess::Unknown }
    }
}

/// Worth decrypting for a preview?
pub fn can_preview(name: &str, size: u64) -> bool {
    size <= MAX_PREVIEW && guess(name) != Guess::Other
}

pub fn can_thumbnail(name: &str, size: u64) -> bool {
    size <= MAX_THUMB && guess(name) == Guess::Image
}

/// Sniff: NUL bytes in the first 4 KiB = binary; must be UTF-8 (a cut multi-byte char at the end is fine).
pub fn looks_like_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(4096)];
    if head.contains(&0) {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(), // only an incomplete character at the cut
    }
}

/// Text for the preview pane: at most [`MAX_TEXT`] bytes, lossy UTF-8. (text, truncated)
pub fn text_of(data: &[u8]) -> (String, bool) {
    let cut = data.len() > MAX_TEXT;
    (String::from_utf8_lossy(&data[..data.len().min(MAX_TEXT)]).into_owned(), cut)
}

/// Short type label for the info pane.
pub fn kind_label(name: &str, is_dir: bool) -> String {
    if is_dir {
        return "Folder".into();
    }
    match ext(name).as_str() {
        "" => "File".into(),
        e => format!("{} file", e.to_uppercase()),
    }
}

/// Symbolic icon name for a file or folder (from the name only; never looks at contents).
pub fn icon_name(name: &str, is_dir: bool) -> &'static str {
    if is_dir {
        return "folder-symbolic";
    }
    let e = ext(name);
    match guess(name) {
        Guess::Image => "image-x-generic-symbolic",
        Guess::Text => "text-x-generic-symbolic",
        _ => match e.as_str() {
            "pdf" | "doc" | "docx" | "odt" => "x-office-document-symbolic",
            "xls" | "xlsx" | "ods" | "csv" => "x-office-spreadsheet-symbolic",
            "ppt" | "pptx" | "odp" => "x-office-presentation-symbolic",
            "mp3" | "m4a" | "flac" | "wav" | "ogg" | "opus" => "audio-x-generic-symbolic",
            "mp4" | "mov" | "mkv" | "avi" | "webm" => "video-x-generic-symbolic",
            "zip" | "gz" | "tgz" | "xz" | "bz2" | "zst" | "7z" | "rar" | "tar" => "package-x-generic-symbolic",
            _ => "text-x-generic-symbolic",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guesses() {
        assert_eq!(guess("a.PNG"), Guess::Image);
        assert_eq!(guess("notes.md"), Guess::Text);
        assert_eq!(guess("README"), Guess::Unknown);
        assert_eq!(guess(".bashrc"), Guess::Unknown);
        assert_eq!(guess("x.zip"), Guess::Other);
        assert!(looks_like_text(b"hello"));
        assert!(!looks_like_text(b"he\0llo"));
    }
}

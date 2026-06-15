//! Tiny std-only persistence helpers shared by the file audit sink, policy
//! store, and token store. No new deps: serde_json + std::fs only.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Append one already-serialized JSON value as a line to `path` (created if
/// absent). Flushes so the line survives an immediate process exit.
pub fn append_jsonl(path: &Path, json_line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(json_line.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()
}

/// Read every non-empty line of a JSON-lines file. Missing file => empty vec.
pub fn read_jsonl_lines(path: &Path) -> std::io::Result<Vec<String>> {
    match File::open(path) {
        Ok(f) => BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .map(Ok)
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Atomically write `contents` to `path` via a temp file + rename.
pub fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp: PathBuf = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }
    std::fs::rename(&tmp, path)
}

/// Read a whole file to a string. Missing file => `None`.
pub fn read_to_string_opt(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_roundtrips_and_survives_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("audit.log");
        append_jsonl(&p, r#"{"a":1}"#).unwrap();
        append_jsonl(&p, r#"{"a":2}"#).unwrap();
        let lines = read_jsonl_lines(&p).unwrap();
        assert_eq!(
            lines,
            vec![r#"{"a":1}"#.to_string(), r#"{"a":2}"#.to_string()]
        );
    }

    #[test]
    fn read_missing_jsonl_is_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let lines = read_jsonl_lines(&dir.path().join("nope.log")).unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn write_atomic_then_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("policies.json");
        write_atomic(&p, r#"{"k":"v"}"#).unwrap();
        assert_eq!(read_to_string_opt(&p).unwrap().unwrap(), r#"{"k":"v"}"#);
    }
}

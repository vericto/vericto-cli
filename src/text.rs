// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Reading SQL sources as text, whatever byte-order mark the editor wrote.
//!
//! Windows tools often start a text file with a byte-order mark: a UTF-8 BOM
//! from Visual Studio, SSMS or PowerShell 5.1's `Set-Content -Encoding UTF8`,
//! and UTF-16LE from PowerShell 5.1's `>` and `Out-File`. Read as plain UTF-8,
//! the UTF-8 BOM reached the parser as part of the first statement, which then
//! failed to parse, and a parse error is allowed: a `DELETE FROM users;` saved
//! that way passed with exit 0. A UTF-16 file was not valid UTF-8 at all, so
//! the run stopped with exit 2. Both are decoded here instead; anything else
//! is read as UTF-8, as before. Line endings are kept as they are (CRLF
//! included), so lines and statement hashes match the file on disk.

use std::io::{self, Read};
use std::path::Path;

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
const UTF16LE_BOM: &[u8] = b"\xFF\xFE";
const UTF16BE_BOM: &[u8] = b"\xFE\xFF";

/// Decodes `bytes` as UTF-8, UTF-16LE or UTF-16BE by their byte-order mark
/// (no mark: UTF-8), without the mark. Invalid text is an `InvalidData` error.
pub fn decode(bytes: Vec<u8>) -> io::Result<String> {
    if let Some(rest) = bytes.strip_prefix(UTF8_BOM) {
        return utf8(rest.to_vec());
    }
    if let Some(rest) = bytes.strip_prefix(UTF16LE_BOM) {
        return utf16(rest, u16::from_le_bytes, "UTF-16LE");
    }
    if let Some(rest) = bytes.strip_prefix(UTF16BE_BOM) {
        return utf16(rest, u16::from_be_bytes, "UTF-16BE");
    }
    utf8(bytes)
}

fn utf8(bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "not valid UTF-8 text (UTF-8 and UTF-16 with a byte-order mark are read)",
        )
    })
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16, name: &str) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, format!("not valid {name} text"));
    let (pairs, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(invalid());
    }
    let units = pairs.iter().map(|&pair| unit(pair));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| invalid())
}

/// Reads the file at `path` as text (see `decode`).
pub fn read_file(path: impl AsRef<Path>) -> io::Result<String> {
    decode(std::fs::read(path)?)
}

/// Reads stdin to the end as text (see `decode`).
pub fn read_stdin() -> io::Result<String> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    decode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v = UTF16LE_BOM.to_vec();
        v.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
        v
    }

    #[test]
    fn plain_utf8_is_unchanged_crlf_included() {
        let sql = "DELETE FROM users;\r\nSELECT 'ñ';\r\n";
        assert_eq!(decode(sql.as_bytes().to_vec()).unwrap(), sql);
    }

    #[test]
    fn the_utf8_bom_is_dropped() {
        let mut v = UTF8_BOM.to_vec();
        v.extend_from_slice(b"DELETE FROM users;\r\n");
        assert_eq!(decode(v).unwrap(), "DELETE FROM users;\r\n");
        // Only a leading mark: a U+FEFF inside the text stays.
        let inner = "SELECT '\u{feff}';".as_bytes().to_vec();
        assert_eq!(decode(inner).unwrap(), "SELECT '\u{feff}';");
    }

    #[test]
    fn utf16_with_a_bom_is_decoded() {
        let sql = "DELETE FROM users; -- ñ 😀\r\n";
        assert_eq!(decode(utf16le(sql)).unwrap(), sql);
        let mut be = UTF16BE_BOM.to_vec();
        be.extend(sql.encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode(be).unwrap(), sql);
    }

    #[test]
    fn invalid_text_is_an_error() {
        assert_eq!(
            decode(vec![0x66, 0xff, 0x6f]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Odd length, and an unpaired surrogate.
        assert!(decode(vec![0xff, 0xfe, 0x41]).is_err());
        assert!(decode(vec![0xff, 0xfe, 0x00, 0xd8]).is_err());
    }
}

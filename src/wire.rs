//! RFC 1939 on the wire: `+OK` and `-ERR` status lines, and the multi-line
//! response that ends at a line holding one dot, with byte-stuffing undone.

use std::io::BufRead;

use transport::error::{Result, TransportError, classify, protocol_error};

/// One status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub ok: bool,
    pub text: String,
}

/// Read one status line.
///
/// # Errors
/// A closed connection, or a line that is neither `+OK` nor `-ERR`.
pub fn read_status(reader: &mut impl BufRead) -> Result<Status> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|e| classify("reading a status line", &e))?;
    if read == 0 {
        return Err(protocol_error("the peer closed the connection"));
    }
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(text) = line.strip_prefix("+OK") {
        return Ok(Status {
            ok: true,
            text: text.trim_start().to_string(),
        });
    }
    if let Some(text) = line.strip_prefix("-ERR") {
        return Ok(Status {
            ok: false,
            text: text.trim_start().to_string(),
        });
    }
    Err(protocol_error(format!("{line:?} is neither +OK nor -ERR")))
}

/// A status that must be `+OK`, or the error the server gave.
///
/// # Errors
/// An `-ERR`, permanent: the server said no and will say it again.
pub fn expect_ok(reader: &mut impl BufRead, what: &str) -> Result<Status> {
    let status = read_status(reader)?;
    if status.ok {
        Ok(status)
    } else {
        Err(TransportError::permanent(format!(
            "the server refused {what}: {}",
            status.text
        )))
    }
}

/// Read a multi-line response up to and excluding the terminating dot, a
/// leading dot on any line un-stuffed. Lines are joined with CRLF and none
/// trails, the same shape `xmip-core-transport-smtp` reads DATA into: mail
/// carries lines, and a message is its lines.
///
/// # Errors
/// A connection that closes before the terminating dot.
pub fn read_multiline(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut first = true;
    loop {
        let mut line = Vec::new();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| classify("reading a multi-line response", &e))?;
        if read == 0 {
            return Err(protocol_error("the response ended before its dot"));
        }
        let body = strip_ending(&line);
        if body == b"." {
            return Ok(out);
        }
        if !first {
            out.extend_from_slice(b"\r\n");
        }
        first = false;
        out.extend_from_slice(body.strip_prefix(b".").unwrap_or(body));
    }
}

/// `bytes` as a multi-line response body: every line CRLF-terminated, a
/// leading dot stuffed, and the terminating dot after.
#[must_use]
pub fn write_multiline(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn strip_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_read() {
        let ok = read_status(&mut &b"+OK 2 messages\r\n"[..]).expect("ok");
        assert!(ok.ok);
        assert_eq!(ok.text, "2 messages");
        let err = read_status(&mut &b"-ERR no such message\r\n"[..]).expect("err");
        assert!(!err.ok);
        assert!(read_status(&mut &b"hello\r\n"[..]).is_err());
        assert!(read_status(&mut &b""[..]).is_err());
        let refused = expect_ok(&mut &b"-ERR nope\r\n"[..], "it").expect_err("refused");
        assert!(!refused.retryable);
    }

    #[test]
    fn multi_line_bodies_round_trip_with_dot_stuffing() {
        for body in [
            &b"Subject: hi\r\n\r\n.starts with a dot\r\nend"[..],
            b"",
            b"one line",
            b"..two dots",
        ] {
            let wire = write_multiline(body);
            assert!(wire.ends_with(b"\r\n.\r\n"));
            let back = read_multiline(&mut wire.as_slice()).expect("read");
            assert_eq!(back, body, "{}", String::from_utf8_lossy(body));
        }
        let trailing = read_multiline(&mut write_multiline(b"a\r\nb\r\n").as_slice());
        assert_eq!(
            trailing.expect("read"),
            b"a\r\nb\r\n",
            "a final break survives"
        );
        assert!(read_multiline(&mut &b"never ends\r\n"[..]).is_err());
    }
}

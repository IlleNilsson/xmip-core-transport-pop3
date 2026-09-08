//! The server's side of one session: what a test puts at the far end, and
//! what a Location that hands mail to a POP3 client directly runs.
//!
//! One maildrop, in memory, one client at a time: the lock RFC 1939 puts on
//! a maildrop is this session existing. Deletes are marked and committed at
//! QUIT, as the protocol says, so a client that drops mid-session loses
//! nothing.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use transport::error::{Result, classify};
use transport::socket;

use crate::wire::write_multiline;

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    messages: Vec<Vec<u8>>,
    deleted: Vec<bool>,
}

impl Session {
    /// Accept one client on `listener`, greet it, and serve `messages`.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(
        listener: &TcpListener,
        messages: Vec<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, _) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let deleted = vec![false; messages.len()];
        let mut session = Self {
            reader,
            writer,
            messages,
            deleted,
        };
        session.ok("xmip ready")?;
        Ok(session)
    }

    /// Serve the client until it quits or drops. Returns what the maildrop
    /// still holds: the messages the client did not delete.
    ///
    /// # Errors
    /// Where the connection broke mid-command.
    pub fn serve(mut self) -> Result<Vec<Vec<u8>>> {
        loop {
            let mut line = String::new();
            let read = self
                .reader
                .read_line(&mut line)
                .map_err(|e| classify("reading a command", &e))?;
            if read == 0 {
                // Dropped: nothing is committed.
                return Ok(self.messages);
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let (verb, argument) = line.split_once(' ').unwrap_or((line, ""));
            match verb.to_ascii_uppercase().as_str() {
                "USER" | "PASS" | "NOOP" => self.ok("")?,
                "STAT" => {
                    let remaining: Vec<&Vec<u8>> = self.live().collect();
                    let octets: usize = remaining.iter().map(|m| m.len()).sum();
                    self.ok(&format!("{} {octets}", remaining.len()))?;
                }
                "LIST" => {
                    let mut lines = String::new();
                    for (i, m) in self.messages.iter().enumerate() {
                        if !self.deleted[i] {
                            use std::fmt::Write as _;
                            let _ = writeln!(lines, "{} {}\r", i + 1, m.len());
                        }
                    }
                    lines.push_str(".\r\n");
                    self.ok("listing follows")?;
                    self.write(lines.as_bytes())?;
                }
                "RETR" => match self.index(argument) {
                    Some(i) => {
                        self.ok("message follows")?;
                        let body = write_multiline(&self.messages[i]);
                        self.write(&body)?;
                    }
                    None => self.err("no such message")?,
                },
                "DELE" => match self.index(argument) {
                    Some(i) => {
                        self.deleted[i] = true;
                        self.ok("marked")?;
                    }
                    None => self.err("no such message")?,
                },
                "RSET" => {
                    self.deleted.iter_mut().for_each(|d| *d = false);
                    self.ok("")?;
                }
                "QUIT" => {
                    self.ok("bye")?;
                    let deleted = self.deleted;
                    return Ok(self
                        .messages
                        .into_iter()
                        .zip(deleted)
                        .filter(|(_, gone)| !gone)
                        .map(|(m, _)| m)
                        .collect());
                }
                _ => self.err("unknown command")?,
            }
        }
    }

    fn live(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.messages
            .iter()
            .zip(&self.deleted)
            .filter(|(_, gone)| !**gone)
            .map(|(m, _)| m)
    }

    fn index(&self, argument: &str) -> Option<usize> {
        let number: usize = argument.trim().parse().ok()?;
        let i = number.checked_sub(1)?;
        (i < self.messages.len() && !self.deleted[i]).then_some(i)
    }

    fn ok(&mut self, text: &str) -> Result<()> {
        self.write(format!("+OK {text}\r\n").as_bytes())
    }

    fn err(&mut self, text: &str) -> Result<()> {
        self.write(format!("-ERR {text}\r\n").as_bytes())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .map_err(|e| classify("writing a response", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a response", &e))
    }
}

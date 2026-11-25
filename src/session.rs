//! The server's side of one session: what a test puts at the far end, and
//! what a Location that hands mail to a POP3 client directly runs.
//!
//! One maildrop, in memory, one client at a time: the lock RFC 1939 puts on
//! a maildrop is this session existing. Deletes are marked and committed at
//! QUIT, as the protocol says, so a client that drops mid-session loses
//! nothing. `UIDL` names each message with a unique-id that every session
//! over the same messages gives it again, unless [`Session::without_uidl`].
//!
//! The login is checked: `PASS` is admitted only where the
//! [`net::login::Check`] the session was handed admits the user `USER`
//! named with it, and refused `-ERR [AUTH]` otherwise (RFC 3206), and no
//! command but the login's and `QUIT` is served until then. Until
//! 2026-11-25 the session took any login.

use std::hash::{DefaultHasher, Hasher};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use net::login::{Check, Offer, Offered};
use transport::error::{Result, classify};
use transport::socket;

use crate::wire::write_multiline;

/// What a refused `PASS` is answered: the response code RFC 3206 gives a
/// login the server does not admit.
pub const REFUSED: &str = "[AUTH] the user or the password is not admitted";

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    messages: Vec<Vec<u8>>,
    deleted: Vec<bool>,
    /// Each message's `UIDL` unique-id, `None` where this maildrop answers
    /// no `UIDL`, an optional command.
    ids: Option<Vec<String>>,
    /// What admits a login.
    check: Check,
    /// The user `USER` named, until `PASS` is answered.
    user: Option<String>,
    /// Whether a login was admitted: the TRANSACTION state.
    admitted: bool,
}

impl Session {
    /// Accept one client on `listener`, greet it, and serve `messages` to
    /// it once `check` admits its login.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(
        listener: &TcpListener,
        messages: Vec<Vec<u8>>,
        check: Check,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, _) = socket::accept_tcp(listener, timeout)?;
        Self::over(stream, messages, check)
    }

    /// Greet a client over an already-open connection and serve `messages`
    /// to it once `check` admits its login — the loopback's maildrop, which
    /// connects to its collector.
    ///
    /// # Errors
    /// Where the connection could not be split or greeted.
    pub fn over(stream: TcpStream, messages: Vec<Vec<u8>>, check: Check) -> Result<Self> {
        let (reader, writer) = socket::split(stream)?;
        let deleted = vec![false; messages.len()];
        let ids = Some(unique_ids(&messages));
        let mut session = Self {
            reader,
            writer,
            messages,
            deleted,
            ids,
            check,
            user: None,
            admitted: false,
        };
        session.ok("xmip ready")?;
        Ok(session)
    }

    /// `USER` and `PASS`, the login's two commands: `PASS` admitted where
    /// the check admits the user `USER` named with its password.
    fn logging_in(&mut self, verb: &str, argument: &str) -> Result<()> {
        match (verb, self.user.take()) {
            ("USER", _) => {
                self.user = Some(argument.to_string());
                self.ok("")
            }
            ("PASS", Some(user)) => {
                let offered = Offered {
                    user: &user,
                    secret: argument,
                };
                self.admitted = (self.check)(&Offer::Password(offered));
                if self.admitted {
                    self.ok("maildrop locked and ready")
                } else {
                    self.err(REFUSED)
                }
            }
            _ => self.err("USER first"),
        }
    }

    /// Answer `UIDL` with `-ERR`, as a server without it does.
    #[must_use]
    pub fn without_uidl(mut self) -> Self {
        self.ids = None;
        self
    }

    /// Serve the client until it quits or drops. Returns what the maildrop
    /// still holds: the messages the client did not delete.
    ///
    /// # Errors
    /// Where the connection broke mid-command.
    pub fn serve(mut self) -> Result<Vec<Vec<u8>>> {
        loop {
            let Some(line) = net::read::line(&mut self.reader)? else {
                // Dropped: nothing is committed.
                return Ok(self.messages);
            };
            let (verb, argument) = line.split_once(' ').unwrap_or((&line, ""));
            let verb = verb.to_ascii_uppercase();
            if !self.admitted && verb != "QUIT" {
                if verb == "USER" || verb == "PASS" {
                    self.logging_in(&verb, argument)?;
                } else {
                    self.err("log in first")?;
                }
                continue;
            }
            match verb.as_str() {
                "NOOP" => self.ok("")?,
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
                "UIDL" => match self.ids.clone() {
                    Some(ids) => {
                        let mut lines = String::new();
                        for (i, id) in ids.iter().enumerate() {
                            if !self.deleted[i] {
                                use std::fmt::Write as _;
                                let _ = writeln!(lines, "{} {id}\r", i + 1);
                            }
                        }
                        lines.push_str(".\r\n");
                        self.ok("unique-id listing follows")?;
                        self.write(lines.as_bytes())?;
                    }
                    None => self.err("no UIDL here")?,
                },
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

/// A unique-id for each of `messages` that every session over the same
/// messages gives it again: a hash of its bytes, and of how many before it
/// had the same bytes.
fn unique_ids(messages: &[Vec<u8>]) -> Vec<String> {
    let mut seen = std::collections::HashMap::new();
    messages
        .iter()
        .map(|message| {
            let before = seen.entry(message.as_slice()).or_insert(0_u32);
            let mut hasher = DefaultHasher::new();
            hasher.write(message);
            let id = format!("{:016x}-{before}", hasher.finish());
            *before += 1;
            id
        })
        .collect()
}

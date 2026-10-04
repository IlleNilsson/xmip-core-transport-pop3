//! The client's side of one POP3 session: log in, list, retrieve, delete,
//! quit — and the deletes only happen at QUIT, which is the maildrop lock
//! doing its work.

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, classify, protocol_error};
use transport::{Login, socket};

use crate::wire::{expect_ok, read_multiline, read_status};

/// The `n word` lines of a `LIST` or `UIDL` listing.
fn pairs(listing: &[u8]) -> Result<Vec<(u32, String)>> {
    String::from_utf8_lossy(listing)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut words = line.split_whitespace();
            let number = words.next().and_then(|n| n.parse().ok());
            number
                .zip(words.next())
                .map(|(number, word)| (number, word.to_string()))
                .ok_or_else(|| protocol_error(format!("{line:?} is not a listing line")))
        })
        .collect()
}

/// One session in the TRANSACTION state.
pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Client {
    /// Connect to `server` and log in, taking the maildrop lock.
    ///
    /// # Errors
    /// Where the server could not be reached, did not greet, or refused the
    /// login — a maildrop another session holds refuses here.
    pub fn connect(server: &str, login: &Login, timeout: Option<Duration>) -> Result<Self> {
        Self::over(socket::connect_tcp(server, timeout)?, login)
    }

    /// Log in over an already-open connection, the server's greeting still
    /// to read — the loopback's collector, which takes the connection the
    /// maildrop made to it.
    ///
    /// # Errors
    /// Where the server did not greet or refused the login.
    pub fn over(stream: TcpStream, login: &Login) -> Result<Self> {
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self { reader, writer };
        expect_ok(&mut client.reader, "the greeting")?;
        client.say(&format!("USER {}", login.user))?;
        expect_ok(&mut client.reader, "the user")?;
        client.say(&format!("PASS {}", login.password))?;
        expect_ok(&mut client.reader, "the login")?;
        Ok(client)
    }

    /// Each message in the maildrop by its number in this session, with
    /// its size in octets, from `LIST`.
    ///
    /// # Errors
    /// Where the server refused or the listing did not read.
    pub fn listing(&mut self) -> Result<Vec<(u32, String)>> {
        self.say("LIST")?;
        expect_ok(&mut self.reader, "the listing")?;
        pairs(&read_multiline(&mut self.reader)?)
    }

    /// Each message in the maildrop by its number in this session, with the
    /// unique-id `UIDL` gives it: the same in every session, and never
    /// another message's (RFC 1939 section 7). `None` where the server has
    /// no `UIDL`, an optional command.
    ///
    /// # Errors
    /// Where the listing did not read.
    pub fn unique_ids(&mut self) -> Result<Option<Vec<(u32, String)>>> {
        self.say("UIDL")?;
        if !read_status(&mut self.reader)?.ok {
            return Ok(None);
        }
        pairs(&read_multiline(&mut self.reader)?).map(Some)
    }

    /// Message `number`, whole.
    ///
    /// # Errors
    /// Where there is no such message, or it did not read.
    pub fn retrieve(&mut self, number: u32) -> Result<Vec<u8>> {
        self.say(&format!("RETR {number}"))?;
        expect_ok(&mut self.reader, "the retrieve")?;
        read_multiline(&mut self.reader)
    }

    /// Mark message `number` for deletion at QUIT.
    ///
    /// # Errors
    /// Where there is no such message.
    pub fn delete(&mut self, number: u32) -> Result<()> {
        self.say(&format!("DELE {number}"))?;
        expect_ok(&mut self.reader, "the delete").map(|_| ())
    }

    /// Leave, committing the deletes and releasing the maildrop.
    ///
    /// # Errors
    /// Where the server could not commit.
    pub fn quit(mut self) -> Result<()> {
        self.say("QUIT")?;
        expect_ok(&mut self.reader, "the quit").map(|_| ())
    }

    fn say(&mut self, command: &str) -> Result<()> {
        self.writer
            .write_all(format!("{command}\r\n").as_bytes())
            .map_err(|e| classify("writing a command", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a command", &e))
    }
}

//! The client's side of one POP3 session: log in, list, retrieve, delete,
//! quit — and the deletes only happen at QUIT, which is the maildrop lock
//! doing its work.

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, classify, protocol_error};
use transport::socket;

use crate::wire::{expect_ok, read_multiline};

/// What a Location presents when it logs in.
#[derive(Clone, Debug, Default)]
pub struct Login {
    pub user: String,
    pub password: String,
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
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self { reader, writer };
        expect_ok(&mut client.reader, "the greeting")?;
        client.say(&format!("USER {}", login.user))?;
        expect_ok(&mut client.reader, "the user")?;
        client.say(&format!("PASS {}", login.password))?;
        expect_ok(&mut client.reader, "the login")?;
        Ok(client)
    }

    /// The message numbers in the maildrop, from `LIST`.
    ///
    /// # Errors
    /// Where the server refused or the listing did not read.
    pub fn numbers(&mut self) -> Result<Vec<u32>> {
        self.say("LIST")?;
        expect_ok(&mut self.reader, "the listing")?;
        let listing = read_multiline(&mut self.reader)?;
        String::from_utf8_lossy(&listing)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or_else(|| protocol_error(format!("{line:?} is not a listing line")))
            })
            .collect()
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

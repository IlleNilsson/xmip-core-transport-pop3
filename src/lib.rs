#![forbid(unsafe_code)]

//! Streams that arrive as mail collected over POP3. One message is one
//! Stream, its number in the maildrop kept beside it.
//!
//! POP3 is the receive half of the oldest integration there is: a partner
//! mails an order, and something collects the mailbox. A Receive Location
//! logs in, lists the maildrop, retrieves every message and deletes what it
//! retrieved, which POP3 commits at QUIT — so a collection that breaks
//! mid-way leaves the maildrop as it was. The send half is SMTP,
//! `xmip-core-transport-smtp`; this transport only receives.
//!
//! The maildrop lock is the protocol's own claim, ADR-0024 clause 4: while
//! this session holds it, no other collector — Xmip node or not — can, and
//! [`Transport::claims`] says so with [`MaildropLock`]. TLS joins with the
//! transport capability's, ADR-0033.
//!
//! The origin URI carries what the server knew: `pop3://server/msg/1`.

pub mod client;
pub mod session;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, Login};
pub use session::Session;
use transport::error::Result;
use transport::socket;
use transport::{Arrived, Artefact, Claimed, Directions, ResourceClaim, Transport};

/// The maildrop lock: taken by logging in, released at QUIT.
///
/// A claim over a whole maildrop rather than one message, because that is
/// what POP3 offers. `is_available` asks by trying to log in, which is the
/// only question the protocol answers.
pub struct MaildropLock {
    server: String,
    login: Login,
    timeout: Option<Duration>,
}

impl ResourceClaim for MaildropLock {
    fn is_available(&self, _artefact: &Artefact) -> Result<bool> {
        match Client::connect(&self.server, &self.login, self.timeout) {
            Ok(client) => client.quit().map(|()| true),
            Err(error) if error.retryable => Err(error),
            Err(_) => Ok(false),
        }
    }

    fn claim(&self, artefact: &Artefact) -> Result<Claimed> {
        // The lock is held by the session that collects; a claim outside one
        // is a check that it can be taken.
        Client::connect(&self.server, &self.login, self.timeout)?.quit()?;
        Ok(Claimed::new(artefact.clone(), "maildrop".to_string()))
    }

    fn release(&self, _claimed: Claimed) -> Result<()> {
        Ok(())
    }
}

pub struct Pop3Transport {
    server: String,
    delete_after_retrieve: bool,
    lock: MaildropLock,
}

impl Pop3Transport {
    /// Collect from `server` as `login`.
    #[must_use]
    pub fn new(server: impl Into<String>, login: Login) -> Self {
        let server = server.into();
        Self {
            server: server.clone(),
            delete_after_retrieve: true,
            lock: MaildropLock {
                server,
                login,
                timeout: None,
            },
        }
    }

    /// Leave retrieved messages in the maildrop rather than deleting them.
    #[must_use]
    pub const fn leaving_mail(mut self) -> Self {
        self.delete_after_retrieve = false;
        self
    }

    /// Give up on a server that stops mid-response.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.lock.timeout = Some(timeout);
        self
    }

    /// Connect and log in.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        Client::connect(&self.server, &self.lock.login, self.lock.timeout)
    }

    /// Bind as the far end a collector connects to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one collector on an already-bound listener, serving
    /// `messages`.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener, messages: Vec<Vec<u8>>) -> Result<Session> {
        Session::accept(listener, messages, self.lock.timeout)
    }
}

impl Transport for Pop3Transport {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    /// Every message in the maildrop, each deleted at QUIT unless the
    /// transport was told to leave them.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let mut arrived = Vec::new();
        for number in client.numbers()? {
            let bytes = client.retrieve(number)?;
            if self.delete_after_retrieve {
                client.delete(number)?;
            }
            arrived.push(Arrived::new(
                format!("pop3://{}/msg/{number}", self.server),
                bytes,
            ));
        }
        client.quit()?;
        Ok(arrived)
    }

    fn send(&self, _target: &str, _bytes: &[u8]) -> Result<()> {
        Err(transport::TransportError::permanent(
            "POP3 only collects; sending mail is xmip-core-transport-smtp",
        ))
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&self.lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Login {
        Login {
            user: "orders".into(),
            password: "secret".into(),
        }
    }

    #[test]
    fn a_collector_takes_the_maildrop_and_the_deletes_commit_at_quit() {
        let far_end =
            Pop3Transport::new("127.0.0.1:0", login()).timing_out_after(Duration::from_secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let collector = std::thread::spawn(move || {
            Pop3Transport::new(address, login())
                .timing_out_after(Duration::from_secs(2))
                .receive()
        });
        let messages = vec![
            b"Subject: one\r\n\r\n.dot first".to_vec(),
            b"Subject: two\r\n\r\nline\r\n".to_vec(),
        ];
        let left = far_end
            .accept_one(&listener, messages.clone())
            .expect("accepting")
            .serve()
            .expect("serving");
        assert!(left.is_empty(), "deleted at QUIT");
        let arrived = collector.join().expect("thread").expect("collecting");
        assert_eq!(arrived.len(), 2);
        assert_eq!(arrived[0].bytes, messages[0]);
        assert_eq!(arrived[1].bytes, messages[1]);
        assert!(arrived[1].origin_uri.ends_with("/msg/2"));
    }

    #[test]
    fn leaving_mail_leaves_it_and_send_is_refused() {
        let far_end =
            Pop3Transport::new("127.0.0.1:0", login()).timing_out_after(Duration::from_secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let collector = std::thread::spawn(move || {
            Pop3Transport::new(address, login())
                .leaving_mail()
                .timing_out_after(Duration::from_secs(2))
                .receive()
        });
        let left = far_end
            .accept_one(&listener, vec![b"kept".to_vec()])
            .expect("accepting")
            .serve()
            .expect("serving");
        assert_eq!(left, vec![b"kept".to_vec()]);
        assert_eq!(
            collector.join().expect("thread").expect("collecting").len(),
            1
        );
        let refused = far_end.send("x", b"y").expect_err("send");
        assert!(!refused.retryable);
        assert!(!far_end.directions().sends());
        assert!(far_end.claims().is_some());
    }

    #[test]
    fn a_refused_login_is_permanent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            std::io::Write::write_all(&mut stream, b"-ERR maildrop locked\r\n").expect("write");
        });
        let Err(error) = Pop3Transport::new(address, login())
            .timing_out_after(Duration::from_secs(2))
            .connect()
        else {
            panic!("connected");
        };
        assert!(!error.retryable);
        assert!(error.message.contains("maildrop locked"));
    }
}

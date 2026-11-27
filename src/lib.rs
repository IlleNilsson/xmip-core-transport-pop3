#![forbid(unsafe_code)]

//! Streams that arrive as mail collected over POP3. One message is one
//! Stream, its number in the maildrop kept beside it.
//!
//! POP3 is the receive half of the oldest integration there is: a Party
//! mails an order, and something collects the mailbox. A Receive Location
//! logs in, lists the maildrop and hands each message back unread; the
//! session stays open until every message has its verdict, deletes what was
//! accepted and quits, which commits the deletes ([`maildrop`]) — so a
//! collection that breaks mid-way leaves the maildrop as it was. A refused
//! message is left in the maildrop, and this Location does not collect it
//! again while it lies there unchanged. The send half is SMTP,
//! `xmip-core-transport-smtp`; this transport only receives.
//!
//! The maildrop lock is the protocol's own claim, ADR-0024 clause 4: while
//! this session holds it, no other collector — Xmip node or not — can, and
//! [`Transport::claims`] says so with [`MaildropLock`]. TLS joins with the
//! transport capability's, ADR-0033.
//!
//! The origin URI carries what the server knew: `pop3://server/msg/1`.
//!
//! **Built with its `declaration` feature alone** the crate is
//! [`declaration`].

#[cfg(feature = "default")]
pub mod client;
#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod maildrop;
#[cfg(feature = "default")]
pub mod session;
#[cfg(feature = "default")]
pub mod wire;

#[cfg(feature = "default")]
use std::{net::TcpListener, time::Duration};

#[cfg(feature = "default")]
pub use client::Client;
#[cfg(feature = "default")]
use declaration::DELETE_AFTER_RETRIEVE;
#[cfg(feature = "default")]
pub use maildrop::{Maildrop, RefusedMail};
#[cfg(feature = "default")]
use net::login::Check;
#[cfg(feature = "default")]
pub use session::Session;
#[cfg(feature = "default")]
use transport::error::{Result, protocol_error};
#[cfg(feature = "default")]
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
#[cfg(feature = "default")]
use transport::{ArrivalIdentity, arrived::one_arrival, listening::Listening, socket};
#[cfg(feature = "default")]
use transport::{
    Arrived, Artifact, Claimed, Configured, Directions, Login, ResourceClaim, Transport,
};
#[cfg(feature = "default")]
use xcore::settings::{Read, Settings};

/// The maildrop lock: taken by logging in, released at QUIT.
///
/// A claim over a whole maildrop rather than one message, because that is
/// what POP3 offers. `is_available` asks by trying to log in, which is the
/// only question the protocol answers.
#[cfg(feature = "default")]
#[derive(Clone)]
pub struct MaildropLock {
    server: String,
    /// Who it logs in as; where its Location names a secret, the secret's
    /// password replaces the password here at each login.
    login: Login,
    /// The secret its Location names, read at each login (ADR-0019,
    /// amendment 2026-11-25).
    secret: Option<transport::Secured>,
    timeout: Option<Duration>,
}

#[cfg(feature = "default")]
impl MaildropLock {
    /// The login presented now: the password the Location's secret holds,
    /// read where it names one.
    ///
    /// # Errors
    /// Where the secret is not set, is no password, or could not be read.
    fn presented(&self) -> Result<Login> {
        transport::secured::logged_in(&self.login, self.secret.as_ref(), "pop3")
    }

    /// Connect and log in, taking the maildrop lock: each session reads the
    /// Location's secret anew.
    fn connect(&self) -> Result<Client> {
        Client::connect(&self.server, &self.presented()?, self.timeout)
    }
}

#[cfg(feature = "default")]
impl ResourceClaim for MaildropLock {
    fn is_available(&self, _artifact: &Artifact) -> Result<bool> {
        match self.connect() {
            Ok(client) => client.quit().map(|()| true),
            Err(error) if error.retryable => Err(error),
            Err(_) => Ok(false),
        }
    }

    fn claim(&self, artifact: &Artifact) -> Result<Claimed> {
        // The lock is held by the session that collects; a claim outside one
        // is a check that it can be taken.
        self.connect()?.quit()?;
        Ok(Claimed::new(artifact.clone(), "maildrop".to_string()))
    }

    fn release(&self, _claimed: Claimed) -> Result<()> {
        Ok(())
    }
}

#[cfg(feature = "default")]
#[derive(Clone)]
pub struct Pop3Transport {
    server: String,
    delete_after_retrieve: bool,
    lock: MaildropLock,
    /// The messages refused and left in the maildrop, shared with the
    /// acknowledgements a receive handed out.
    refused: RefusedMail,
}

#[cfg(feature = "default")]
impl Pop3Transport {
    /// Collect from `server` as `login`.
    #[must_use]
    pub fn new(server: impl Into<String>, login: Login) -> Self {
        let server = server.into();
        Self {
            server: server.clone(),
            delete_after_retrieve: DELETE_AFTER_RETRIEVE,
            lock: MaildropLock {
                server,
                login,
                secret: None,
                timeout: None,
            },
            refused: RefusedMail::default(),
        }
    }

    /// Leave accepted messages in the maildrop rather than deleting them.
    #[must_use]
    pub const fn leaving_mail(mut self) -> Self {
        self.delete_after_retrieve = false;
        self
    }

    /// Connect and log in, the password the Location's secret holds read
    /// now where it names one.
    ///
    /// # Errors
    /// Where the secret could not be presented, or the server could not be
    /// reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.lock.connect()
    }

    /// Bind as the far end a collector connects to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one collector on an already-bound listener, serving
    /// `messages` once `check` admits its login.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(
        &self,
        listener: &TcpListener,
        messages: Vec<Vec<u8>>,
        check: Check,
    ) -> Result<Session> {
        Session::accept(listener, messages, check, self.lock.timeout)
    }

    /// Every message the logged-in client's maildrop holds, handed back
    /// unread on the session held open until each has its verdict
    /// ([`Maildrop`]); `server` names the origin.
    fn collect(&self, client: Client, server: &str, most: usize) -> Result<Vec<Arrived>> {
        Maildrop::collect(
            client,
            most,
            |number| format!("pop3://{server}/msg/{number}"),
            self.delete_after_retrieve,
            &self.refused,
        )
    }
}

#[cfg(feature = "default")]
impl Transport for Pop3Transport {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn directions(&self) -> Directions {
        Directions::RECEIVE
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered(
            "the maildrop is locked by the session until every message is told",
        )
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a session lists the maildrop and returns")
    }

    /// Every message in the maildrop not refused before as it lies, handed
    /// back unread: each retrieved when the runtime first reads it, marked
    /// deleted on `Accepted` unless the transport was told to leave mail,
    /// left and remembered on `Refused`, left on `Failed`, and the
    /// session quits after the last verdict, committing the deletes. A
    /// session of its own each receive: POP3 fixes the maildrop at login and
    /// commits deletes at QUIT, so a kept one would see no new mail and
    /// remove none.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        self.collect(self.connect()?, &self.server, most)
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("nothing is sent, so nothing is held: POP3 only collects")
    }

    fn send_from(&self, _target: &str, _outgoing: transport::Outgoing<'_>) -> Result<()> {
        Err(transport::TransportError::permanent(
            "POP3 only collects; sending mail is xmip-core-transport-smtp",
        ))
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&self.lock)
    }
}

#[cfg(feature = "default")]
impl Configured for Pop3Transport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.lock.timeout)
    }

    /// The password is the secret the Location names, never a setting; the
    /// login is built without it.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let login = Login {
            user: settings
                .optional_text("user")
                .unwrap_or_default()
                .to_string(),
            password: String::new(),
        };
        let mut transport = Self::new(address, login);
        if settings.optional_boolean("delete_after_retrieve") == Some(false) {
            transport = transport.leaving_mail();
        }
        Ok(transport)
    }

    /// The password the Location's secret holds, as `PASS` for its `user`,
    /// read at each login.
    fn secured_by(mut self, secret: transport::Secured) -> Result<Self> {
        self.lock.secret = Some(secret);
        Ok(self)
    }
}

#[cfg(feature = "default")]
impl Pop3Transport {
    /// Both ends on this machine: an ephemeral local port, a probe login,
    /// the loopback timeout on every read.
    ///
    /// POP3 only collects, so the bytes can only travel from a maildrop to a
    /// collector. The near end is therefore the maildrop, serving the
    /// payload as its one message, and the far end the collector that takes
    /// it — and since the far end is the side with the address, the maildrop
    /// connects to the collector. A socket has no notion of which side
    /// speaks server; the protocol is the same RFC 1939 either way.
    #[must_use]
    pub fn loopback() -> Self {
        let login = Login {
            user: "probe".to_string(),
            password: "probe".to_string(),
        };
        Self::new("127.0.0.1:0", login).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

#[cfg(feature = "default")]
impl Loopback for Pop3Transport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a mail names its sender in itself, a message identity; the peer is the server",
        )
    }

    /// A bound listener waiting for the one maildrop that connects to be
    /// collected.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let transport = self.clone();
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| {
                let (stream, peer) = socket::accept_tcp(listener, transport.lock.timeout)?;
                let client = Client::over(stream, &transport.lock.presented()?)?;
                one_arrival(
                    transport.collect(client, &peer.to_string(), 1)?,
                    "collected",
                )?
                .taken()
            },
            self.bind()?,
        )))
    }

    /// A maildrop of its own at `address`, admitting the one login this
    /// collector presents.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let login = self.lock.presented()?;
        let check = net::login::only(login.user, login.password);
        let stream = socket::connect_tcp(address, self.lock.timeout)?;
        let left = Session::over(stream, vec![payload.to_vec()], check)?.serve()?;
        if left.is_empty() {
            Ok(())
        } else {
            Err(protocol_error(
                "the collector left the message in the maildrop",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;
    use xcore::settings::Applies;

    fn login() -> Login {
        Login {
            user: "orders".into(),
            password: "secret".into(),
        }
    }

    /// The check a far end admits [`login`] by, and no other.
    fn admitting() -> Check {
        let login = login();
        net::login::only(login.user, login.password)
    }

    #[test]
    fn pop3_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(Pop3Transport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("user".to_string(), Given::Text("orders".to_string())),
            ("delete_after_retrieve".to_string(), Given::Boolean(false)),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built = Pop3Transport::open("mail:110", Applies::Receive, &given).expect("built");
        assert_eq!(built.server, "mail:110");
        assert_eq!(built.lock.login.user, "orders");
        assert!(!built.delete_after_retrieve);
        assert_eq!(built.lock.timeout, Some(Duration::from_secs(2)));
        let Err(refused) = Pop3Transport::open("mail:110", Applies::Receive, &given[1..]) else {
            panic!("user is required");
        };
        assert!(refused.message.contains("\"user\""), "{}", refused.message);
    }

    #[test]
    fn the_loopback_serves_one_message_and_collects_it() {
        let message = b"Subject: x\r\n\r\n.dot";
        let arrived = Pop3Transport::loopback().round(message).expect("round");
        assert_eq!(arrived.bytes, message);
        assert!(arrived.origin_uri.starts_with("pop3://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/msg/1"));
        let long = vec![0x2a; 100_000];
        assert_eq!(
            Pop3Transport::loopback().round(&long).expect("long").bytes,
            long
        );
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let transport = Pop3Transport::loopback();
        assert!(transport.ceiling().is_none());
        for (name, bytes) in edge_payloads() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
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
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()
        });
        let messages = vec![
            b"Subject: one\r\n\r\n.dot first".to_vec(),
            b"Subject: two\r\n\r\nline\r\n".to_vec(),
        ];
        let left = far_end
            .accept_one(&listener, messages.clone(), admitting())
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
    fn a_failed_and_a_refused_message_stay_and_an_accepted_one_is_deleted_at_quit() {
        let far_end =
            Pop3Transport::new("127.0.0.1:0", login()).timing_out_after(Duration::from_secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let collector = std::thread::spawn(move || {
            let mut arrived = Pop3Transport::new(address, login())
                .timing_out_after(Duration::from_secs(2))
                .receive()?;
            assert!(arrived.iter().all(Arrived::defers));
            // The first read and failed, the second refused, the third
            // accepted: the last verdict quits.
            let (_, mut body, acknowledgement) = arrived.remove(0).into_parts();
            let mut read = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
            drop(body);
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            arrived.remove(0).refused(transport::Refusal::Forbidden)?;
            let accepted = arrived.remove(0).taken()?;
            Ok::<_, transport::TransportError>((read, accepted))
        });
        let messages = vec![
            b"failed\r\n".to_vec(),
            b"refused\r\n".to_vec(),
            b"accepted\r\n".to_vec(),
        ];
        let left = far_end
            .accept_one(&listener, messages.clone(), admitting())
            .expect("accepting")
            .serve()
            .expect("serving");
        let (read, accepted) = collector.join().expect("thread").expect("collecting");
        assert_eq!(read, messages[0]);
        assert_eq!(accepted.bytes, messages[2]);
        assert_eq!(
            left,
            vec![messages[0].clone(), messages[1].clone()],
            "the refused message is the only copy, and is left in the maildrop"
        );
    }

    /// One receive by `near` from `far_end` serving `messages` — answering
    /// no `UIDL` unless `uidl` — each message read and refused where it
    /// begins `refused`, accepted otherwise: what the maildrop holds after,
    /// and what was read.
    fn round(
        far_end: &Pop3Transport,
        listener: &TcpListener,
        near: &Pop3Transport,
        messages: &[&[u8]],
        uidl: bool,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let near = near.clone();
        let collector = std::thread::spawn(move || {
            let mut read = Vec::new();
            for arrived in near.receive()? {
                let (_, mut body, acknowledgement) = arrived.into_parts();
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut body, &mut bytes).expect("reading");
                drop(body);
                let verdict = if bytes.starts_with(b"refused") {
                    transport::Verdict::Refused(transport::Refusal::Forbidden)
                } else {
                    transport::Verdict::Accepted
                };
                acknowledgement.acknowledge(verdict)?;
                read.push(bytes);
            }
            Ok::<_, transport::TransportError>(read)
        });
        let messages = messages.iter().map(|m| m.to_vec()).collect();
        let session = far_end
            .accept_one(listener, messages, admitting())
            .expect("accepting");
        let session = if uidl {
            session
        } else {
            session.without_uidl()
        };
        let left = session.serve().expect("serving");
        (left, collector.join().expect("thread").expect("collecting"))
    }

    #[test]
    fn a_refused_message_stays_and_is_not_collected_again_while_it_lies_unchanged() {
        const REFUSED: &[u8] = b"refused\r\n";
        // As long as the refused one: one size, another message.
        const ANOTHER: &[u8] = b"another\r\n";
        const ONE: &[u8] = b"one\r\n";
        let wait = Duration::from_secs(2);
        for uidl in [true, false] {
            let far_end = Pop3Transport::new("127.0.0.1:0", login()).timing_out_after(wait);
            let (listener, address) = far_end.bind().expect("binding");
            let near = Pop3Transport::new(address, login()).timing_out_after(wait);
            let (left, read) = round(&far_end, &listener, &near, &[REFUSED, ONE], uidl);
            assert_eq!(read, [REFUSED, ONE], "uidl {uidl}");
            assert_eq!(left, [REFUSED], "uidl {uidl}: the refused one stays");
            let (left, read) = round(&far_end, &listener, &near, &[REFUSED, ANOTHER], uidl);
            assert_eq!(
                read,
                [ANOTHER],
                "uidl {uidl}: the refused one is not collected again"
            );
            assert_eq!(left, [REFUSED], "uidl {uidl}");
            let (left, read) = round(&far_end, &listener, &near, &[REFUSED], uidl);
            assert!(read.is_empty(), "uidl {uidl}");
            assert_eq!(left, [REFUSED], "uidl {uidl}");
            // A node started again remembers nothing: collected once more.
            let restarted = Pop3Transport::new(near.server.clone(), login()).timing_out_after(wait);
            let (left, read) = round(&far_end, &listener, &restarted, &[REFUSED], uidl);
            assert_eq!(
                (left, read),
                (vec![REFUSED.to_vec()], vec![REFUSED.to_vec()])
            );
        }
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
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()
        });
        let left = far_end
            .accept_one(&listener, vec![b"kept".to_vec()], admitting())
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
    fn the_password_is_the_locations_secret_read_at_each_login() {
        use transport::secured::Kept;
        use xcore::SecretKind::Password;
        use xcore::settings::Given;
        let kept = std::sync::Arc::new(Kept::default());
        let drawn = Kept::drawn();
        let far_end =
            Pop3Transport::new("127.0.0.1:0", login()).timing_out_after(Duration::from_secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let given = [
            ("user".to_string(), Given::Text("orders".to_string())),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let near = Pop3Transport::open(&format!("pop3://{address}"), Applies::Receive, &given)
            .expect("built")
            .secured_by(kept.secured("partner-x.pop3"))
            .expect("kept");
        let unset = near.receive().expect_err("not set");
        assert!(unset.retryable, "asked again at the next login");
        assert!(unset.message.contains("is not set"), "{unset}");

        let check = net::login::only("orders", drawn.clone());
        kept.set("partner-x.pop3", Password, &format!("{drawn}-wrong"));
        let collecting = near.clone();
        let collector = std::thread::spawn(move || collecting.receive().err());
        let left = far_end
            .accept_one(&listener, vec![b"kept".to_vec()], check.clone())
            .expect("accepting")
            .serve()
            .expect("serving");
        assert_eq!(left, [b"kept".to_vec()], "nothing is served before a login");
        let wrong = collector.join().expect("thread").expect("refused");
        assert!(wrong.message.contains(session::REFUSED), "{wrong}");
        assert!(!wrong.retryable, "{wrong}");

        kept.set("partner-x.pop3", Password, &drawn);
        let collecting = near.clone();
        let collector = std::thread::spawn(move || {
            collecting
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()
        });
        let left = far_end
            .accept_one(&listener, vec![b"mail".to_vec()], check)
            .expect("accepting")
            .serve()
            .expect("serving");
        assert!(left.is_empty(), "collected and deleted");
        let collected = collector.join().expect("thread").expect("collected");
        assert_eq!(collected[0].bytes, b"mail");
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

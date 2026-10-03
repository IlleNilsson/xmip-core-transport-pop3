//! One collection's session, held open across its receive cycle.
//!
//! POP3 fixes the maildrop at login and commits deletes at QUIT, so the
//! session that listed the messages is the one that must delete them: a
//! receive logs in, lists, and hands each message back unread, and the
//! session stays open, holding the maildrop lock, until every message of
//! the receive has its verdict. Each body retrieves its message (`RETR`)
//! when the runtime first reads it; `Accepted` marks it deleted (`DELE`),
//! `Refused` marks nothing. The last verdict (`transport::together`) sends `QUIT`, which commits
//! the accepted deletes and leaves the refused messages in the maildrop
//! for the next receive. `RSET` is never sent: it would undo the accepted
//! deletes of the same session along with nothing refused.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::fetched;
use transport::error::{Result, protocol_error};
use transport::together::together;
use transport::{Arrived, Verdict};

use crate::client::Client;

/// The session a receive listed on, held until its messages' last verdict
/// (`transport::together`).
pub struct Maildrop {
    /// `None` once it has quit.
    client: Mutex<Option<Client>>,
}

impl Maildrop {
    /// Every message `client` lists, as arrivals from `origin` of each
    /// number, deleted on `Accepted` where `delete` says; the session quits
    /// at once where there are none, and after the last verdict otherwise.
    ///
    /// # Errors
    /// Where the listing failed, or an empty maildrop could not be left.
    pub fn collect(
        mut client: Client,
        origin: impl Fn(u32) -> String,
        delete: bool,
    ) -> Result<Vec<Arrived>> {
        let numbers = client.numbers()?;
        if numbers.is_empty() {
            client.quit()?;
            return Ok(Vec::new());
        }
        let maildrop = Arc::new(Self {
            client: Mutex::new(Some(client)),
        });
        let (deleting, quitting) = (Arc::clone(&maildrop), Arc::clone(&maildrop));
        let listed = numbers.clone();
        let acknowledgements = together(
            numbers.len(),
            move |at, verdict| match verdict {
                // A maildrop has no place for a refused message: deleted too.
                Verdict::Accepted | Verdict::Refused(_) if delete => {
                    deleting.with(|client| client.delete(listed[at]))
                }
                Verdict::Accepted | Verdict::Refused(_) | Verdict::Failed => Ok(()),
            },
            // The last verdict quits, committing the deletes; a message let
            // go without one is marked nothing.
            move |_| quitting.client().take().map_or(Ok(()), Client::quit),
        );
        Ok(numbers
            .into_iter()
            .zip(acknowledgements)
            .map(|(number, acknowledgement)| {
                let maildrop = Arc::clone(&maildrop);
                let body = fetched(move || maildrop.with(|client| client.retrieve(number)));
                Arrived::new(origin(number), body, acknowledgement)
            })
            .collect())
    }

    fn client(&self) -> MutexGuard<'_, Option<Client>> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<T>(&self, act: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        match &mut *self.client() {
            Some(client) => act(client),
            None => Err(protocol_error("the collection's session had already quit")),
        }
    }
}

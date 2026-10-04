//! One collection's session, held open across its receive cycle.
//!
//! POP3 fixes the maildrop at login and commits deletes at QUIT, so the
//! session that listed the messages is the one that must delete them: a
//! receive logs in, lists, and hands each message back unread, and the
//! session stays open, holding the maildrop lock, until every message of
//! the receive has its verdict. Each body retrieves its message (`RETR`)
//! when the runtime first reads it; `Accepted` marks it deleted (`DELE`),
//! `Refused` and `Failed` mark nothing. The last verdict
//! (`transport::together`) sends `QUIT`, which commits the accepted
//! deletes and leaves the others in the maildrop. `RSET` is never sent: it
//! would undo the accepted deletes of the same session along with nothing
//! refused.
//!
//! A refusal is not a consumption: the refused message is the only copy,
//! and stays in the maildrop. So the Location remembers it ([`Refused`])
//! and does not collect it again while it lies there unchanged. A message
//! number holds for one session only; what names a message across sessions
//! is the unique-id `UIDL` gives it, which never changes (RFC 1939 section
//! 7). A server without `UIDL` names none, and there a refused message is
//! remembered by its size, stamped with a hash of its bytes — retrieved
//! again only for a listed message of a size that was refused. There a size
//! is remembered once: where two messages of one size lie, a refused one
//! may be collected and refused again, never lost. The memory is the node
//! process's: a node started again collects it once more.

use std::hash::{DefaultHasher, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::fetched;
use transport::error::{Result, protocol_error};
use transport::together::together;
use transport::{Acknowledgement, Arrived, Refused, Verdict};

use crate::client::Client;

/// The messages a Location refused and left in the maildrop: by their
/// `UIDL` unique-id with no stamp, or, where the server has no `UIDL`, by
/// their size with a hash of their bytes.
pub type RefusedMail = Refused<String, Option<u64>>;

/// The session a receive listed on, held until its messages' last verdict
/// (`transport::together`).
pub struct Maildrop {
    /// `None` once it has quit.
    client: Mutex<Option<Client>>,
}

impl Maildrop {
    /// Every message `client` lists that `refused` does not hold as it
    /// lies, as arrivals from `origin` of each number, deleted on
    /// `Accepted` where `delete` says and remembered in `refused` on
    /// `Refused`; the session quits at once where there are none, and after
    /// the last verdict otherwise.
    ///
    /// # Errors
    /// Where the listing failed, or an empty maildrop could not be left.
    pub fn collect(
        mut client: Client,
        origin: impl Fn(u32) -> String,
        delete: bool,
        refused: &RefusedMail,
    ) -> Result<Vec<Arrived>> {
        let (listed, unique) = match client.unique_ids()? {
            Some(ids) => (ids, true),
            None => (client.listing()?, false),
        };
        let listed = refused.sift(
            listed,
            |(_, name)| name,
            |(number, _)| {
                if unique {
                    Some(None)
                } else {
                    client
                        .retrieve(*number)
                        .ok()
                        .map(|bytes| Some(digest(&bytes)))
                }
            },
        );
        if listed.is_empty() {
            client.quit()?;
            return Ok(Vec::new());
        }
        let maildrop = Arc::new(Self {
            client: Mutex::new(Some(client)),
        });
        let (deleting, quitting) = (Arc::clone(&maildrop), Arc::clone(&maildrop));
        let numbers: Vec<u32> = listed.iter().map(|(number, _)| *number).collect();
        let acknowledgements = together(
            listed.len(),
            move |at, verdict| match verdict {
                Verdict::Accepted if delete => deleting.with(|client| client.delete(numbers[at])),
                Verdict::Accepted | Verdict::Refused(_) | Verdict::Failed => Ok(()),
            },
            // The last verdict quits, committing the deletes; a message let
            // go without one is marked nothing.
            move |_| quitting.client().take().map_or(Ok(()), Client::quit),
        );
        Ok(listed
            .into_iter()
            .zip(acknowledgements)
            .map(|((number, name), acknowledgement)| {
                let told = if unique {
                    refused.remembering(name, None, acknowledgement)
                } else {
                    Self::hashed(&maildrop, refused, number, name, acknowledgement)
                };
                let maildrop = Arc::clone(&maildrop);
                let body = fetched(move || maildrop.with(|client| client.retrieve(number)));
                Arrived::new(origin(number), body, told)
            })
            .collect())
    }

    /// `told`, remembering `name` in `refused` with a hash of message
    /// `number` as the maildrop holds it when the cycle refuses it: asked
    /// then, while the session is still open, so a message never read is
    /// never retrieved for it. A hash that could not be had remembers
    /// nothing, and the message is collected again.
    fn hashed(
        maildrop: &Arc<Self>,
        refused: &RefusedMail,
        number: u32,
        name: String,
        told: Acknowledgement,
    ) -> Acknowledgement {
        let (maildrop, refused) = (Arc::clone(maildrop), refused.clone());
        Acknowledgement::deferred(move |verdict| {
            if matches!(verdict, Verdict::Refused(_))
                && let Ok(bytes) = maildrop.with(|client| client.retrieve(number))
            {
                refused.remember(name, Some(digest(&bytes)));
            }
            told.acknowledge(verdict)
        })
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

/// A hash of a message's bytes: what says it is the one refused.
fn digest(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

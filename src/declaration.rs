//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Whether an accepted message is deleted, unless told otherwise.
pub const DELETE_AFTER_RETRIEVE: bool = true;

/// Every setting a Location takes beyond its address, the server's host
/// and port: where a Receive Location logs in. POP3 only collects, so every
/// setting is a Receive Location's.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "user",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The mailbox user a Location logs in as.",
            applies: Applies::Receive,
        },
        Setting {
            name: "delete_after_retrieve",
            kind: Kind::Boolean,
            presence: Presence::Default(Fixed::Boolean(DELETE_AFTER_RETRIEVE)),
            meaning: "Whether a message is deleted once its receive cycle accepted it, \
                      committed at QUIT.",
            applies: Applies::Receive,
        },
        transport::configured::timeout(
            Applies::Receive,
            None,
            "How long a server that stops mid-response is waited on; unbounded \
             when left out.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["pop3"];

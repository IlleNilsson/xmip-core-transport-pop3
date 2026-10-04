# xmip-core-transport-pop3

POP3 transport: one collected message is one Stream; a Receive Location takes the maildrop, retrieves and deletes, the deletes committed at QUIT. RFC 1939. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The login is the transport capability's `Login`.

A receive connects, logs in and quits every time, unlike the broker, SQL and file-share technologies, whose receives keep their session in the capability's pool. That is POP3's own: a session holds the maildrop as it was at login, sees nothing that arrives after, and commits its deletes only at QUIT (RFC 1939 sections 6 and 8), so a kept session would neither find new mail nor ever remove what it retrieved.

## Acknowledgement

A message is consumed only after the runtime's whole receive cycle. A receive logs in, lists the maildrop and hands each message back unread, and its session stays open, holding the maildrop lock, until every message of the receive has its verdict. Each body retrieves its message (`RETR`) when the runtime first reads it; a POP3 response is read whole by this crate's wire, so a message is whole in memory, one at a time. `Accepted` marks it deleted (`DELE`) unless `delete_after_retrieve = false`. `Refused` marks nothing: a refusal is not a consumption, and a Stream refused at a transport gate was never written to the Ledger, so the message is the only copy and stays in the maildrop. The Location remembers it (`transport::Refused`) by the unique-id `UIDL` gives it, which names one message in every session and never changes (RFC 1939 section 7), and does not collect it again while it lies there; a server without `UIDL` has it remembered by its size and a hash of its bytes, retrieved again only for a listed message of a size that was refused. The memory is the node process's, so a node started again collects it once more. `Failed` marks nothing. The last verdict (`transport::together`) sends `QUIT`, which commits the accepted deletes and leaves the refused and failed messages in the maildrop. `RSET` is never sent, since it would also undo the accepted deletes of the same session. Until 2026-10-02 a receive retrieved and deleted every message and quit before handing them back.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

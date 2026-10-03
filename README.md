# xmip-core-transport-pop3

POP3 transport: one collected message is one Stream; a Receive Location takes the maildrop, retrieves and deletes, the deletes committed at QUIT. RFC 1939. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The login is the transport capability's `Login`.

A receive connects, logs in and quits every time, unlike the broker, SQL and file-share technologies, whose receives keep their session in the capability's pool. That is POP3's own: a session holds the maildrop as it was at login, sees nothing that arrives after, and commits its deletes only at QUIT (RFC 1939 sections 6 and 8), so a kept session would neither find new mail nor ever remove what it retrieved.

## Acknowledgement

A message is consumed only after the runtime's whole receive cycle. A receive logs in, lists the maildrop and hands each message back unread, and its session stays open, holding the maildrop lock, until every message of the receive has its verdict. Each body retrieves its message (`RETR`) when the runtime first reads it; a POP3 response is read whole by this crate's wire, so a message is whole in memory, one at a time. `Accepted` marks it deleted (`DELE`) unless `delete_after_retrieve = false`. `Refused` marks it deleted too, under the same setting: a maildrop has no place for a refused message, the runtime audited the refusal, and from Message creation on the Stream is kept in Xmip (ADR-0013); left, it would be collected and refused again on every receive. `Failed` marks nothing. The last verdict (`transport::together`) sends `QUIT`, which commits the deletes and leaves the failed messages in the maildrop for the next receive. `RSET` is never sent, since it would also undo the accepted deletes of the same session. Until 2026-10-02 a receive retrieved and deleted every message and quit before handing them back.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

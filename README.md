# xmip-core-transport-pop3

POP3 transport: one collected message is one Stream; a Receive Location takes the maildrop, retrieves and deletes, the deletes committed at QUIT. RFC 1939. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The login is the transport capability's `Login`.

A receive connects, logs in and quits every time, unlike the broker, SQL and file-share technologies, whose receives keep their session in the capability's pool. That is POP3's own: a session holds the maildrop as it was at login, sees nothing that arrives after, and commits its deletes only at QUIT (RFC 1939 sections 6 and 8), so a kept session would neither find new mail nor ever remove what it retrieved.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

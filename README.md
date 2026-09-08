# xmip-core-transport-pop3

POP3 transport: one collected message is one Stream; a Receive Location takes the maildrop, retrieves and deletes, the deletes committed at QUIT. RFC 1939. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

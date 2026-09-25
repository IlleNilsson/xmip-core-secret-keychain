# xmip-core-secret-keychain

The macOS keychain as the key home's store (ADR-0063 clause 4). A technology
of [xmip-core-secret](https://github.com/IlleNilsson/xmip-core-secret).

A key-encryption key is thirty-two random bytes kept as a generic password
item of the Service Identity's keychain: the service is the one
`Keychain::new` is given (`Xmip` by convention), the account is the key's
name. The keychain encrypts it and hands it only to the identity that owns
it. An existing item is never replaced.

`Keychain` is a `secret::KekHolder`; `secret::Held::new(Keychain::new("Xmip"))`
is the `KeyStore`. The Security framework is reached through the
`security-framework` crate, whose safe functions hold the FFI, so this crate
keeps `unsafe_code = "forbid"`. On other platforms the crate is empty.

## Verification

**Not run on macOS.** The estate's machines are Windows and AlmaLinux; the
crate builds there as the empty crate it is on those platforms, and its
macOS code and tests (a key wraps and unwraps through the keychain, a missing
key is refused) wait for a macOS machine. ADR-0015 clause 7 makes macOS a
development target. The workflow is manual-only and calls the versioned
shared workflow at `IlleNilsson/.github@v1`.

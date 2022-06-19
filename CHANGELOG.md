# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Security
- `Ed25519ExpandedPrivateKey.sign` no longer takes a `publicKey` argument. The
  previous API allowed the caller to control how the public key was cached in
  memory, but it created an opportunity for misuse: if two signatures were
  created using different public keys, the private scalar could be recovered
  from the signatures (see [here][pubkey-2014] and [here][pubkey-2022] for
  details). We now always cache the public key ourselves to provide a safer
  signing API.

[pubkey-2014]: https://github.com/jedisct1/libsodium/issues/170
[pubkey-2022]: https://github.com/MystenLabs/ed25519-unsafe-libs

## [0.1.0] - 2020-04-13
Initial release!

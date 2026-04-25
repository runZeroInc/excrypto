excrypto
========

[![GoDoc](https://godoc.org/github.com/runZeroInc/excrypto?status.svg)](https://godoc.org/github.com/runZeroInc/excrypto)

excrypto offers specialized versions of the Go `crypto`, `crypto/tls`, `crypto/x509`,
`encoding/asn1`, and `golang.org/x/crypto` packages designed for security research,
network reconnaissance, and probing of legacy or misconfigured systems.

excrypto is based on Google's Go [crypto](https://github.com/golang/go/tree/master/src/crypto)
source, Google's Go [x/crypto](https://cs.opensource.google/go/x/crypto) library, and the
[ZCrypto](https://github.com/zmap/zcrypto/) project.

## Security

* excrypto is intended to support security research and **does not make any
  guarantees on confidentiality, integrity, or availability**.
* excrypto **must not** be used to implement authentication or to transfer
  sensitive information over untrusted networks.
* excrypto deliberately accepts cryptographic primitives, key sizes, signature
  algorithms, and protocol behaviors that upstream Go rejects as insecure. This
  is a feature, not a bug.
* excrypto may have more bugs, including security vulnerabilities, compared to
  upstream Go.

If you find an *unintentional* security issue, contact security[at]runzero.com.

## Upstream baselines

The current snapshot is rebased on top of:

| Source                           | Pin                                        |
| -------------------------------- | ------------------------------------------ |
| `golang/go` `src/crypto`         | [`refs/crypto.hash`](refs/crypto.hash)     |
| `golang/x/crypto`                | [`refs/xcrypto.hash`](refs/xcrypto.hash)   |

`scripts/crypto_diff.sh` and `scripts/xcrypto_diff.sh` regenerate the diffs
against those upstream commits; `scripts/xcrypto_rewrite.sh` performs the
package-path rewrites so upstream code can compile under
`github.com/runZeroInc/excrypto/...`.

## How this fork differs from upstream

The headline use case is **talking to old, insecure, or misconfigured systems
and parsing whatever they send back**. Where upstream Go has tightened policy
over the years to refuse anything weak, excrypto re-opens those doors.

### Permissive parsing

* `encoding/asn1` is the ZCrypto fork that tolerates non-canonical lengths,
  trailing data, malformed `UTCTime`/`GeneralizedTime`, length-zero fields, and
  other RFC violations seen in deployed certificates.
* `crypto/x509` permits negative serial numbers, unknown critical extensions
  (with reasons surfaced rather than fatal errors), permissive name constraints
  (registered IDs are decoded with the OID tag re-prepended; permitted subtrees
  cover directory names and EDI party names), zero/negative DSA parameters
  reported as parse errors instead of panics, and many other bug-compat hacks.
* `crypto/x509.Certificate` carries a much richer set of parsed fields than
  upstream — issuer/subject helpers, validation status sets, CT SCT data,
  extension blob copies for round-tripping, etc.
* `Certificate.Verify()` is the ZCrypto-style three-set return:
  `(current, expired, never-valid)` chains plus an error, instead of a single
  hard failure.

### Weak/legacy primitives kept alive

* **Tiny RSA keys.** `crypto/rsa.checkKeySize` is a no-op. `GenerateKey`
  accepts arbitrarily small modulus sizes (verified at 64/128/256/384/512
  bits). PKCS#1 v1.5, PSS, and OAEP all run if the math fits.
* **MD5 signatures.** `crypto/x509.CreateCertificate` will sign with MD5;
  `ParseCertificate`/`CheckSignature` verify MD5-RSA signatures.
* **SHA-1 signatures.** Fully supported for both signing and verification on
  RSA and ECDSA, including with weak keys.
* **DSA.** `crypto/dsa` is preserved (upstream removed it from cert parsing
  paths). `crypto/x509` parses DSA public keys and recognizes
  `DSAWithSHA1`/`DSAWithSHA256` OIDs.
* **ECDSA on P-224** and other legacy NIST curves: kept usable for
  generation, signing, parsing, and verification.
* **RC2** lives at [`crypto/ssl3/rc2`](crypto/ssl3/rc2) with
  `NewCipherReducedStrength` for 40/56/64/128-bit keys, used by SSL 3.0
  cipher suites.
* **RC4**, **DES**, **3DES**, **MD5**, **SHA-1** are all retained as
  first-class packages even after upstream deprecations.

### TLS / SSL stacks

excrypto ships **three parallel SSL/TLS stacks** spanning every wire
version from SSL 2.0 to TLS 1.3:

* [`crypto/tls`](crypto/tls) tracks modern upstream Go (TLS 1.0–1.3, TLS 1.3
  primary). It re-enables MD5/SHA-1 signature schemes and weak key
  acceptance for handshake research.
* [`crypto/ssl3/tls`](crypto/ssl3/tls) is the ZCrypto-derived legacy stack
  that still speaks **SSL 3.0 through TLS 1.2**. It exposes a structured
  `HandshakeLog` (`ServerHandshake`, `ClientHello`, `ServerHello`,
  `ServerKeyExchange`, `Heartbleed`, etc.) for capturing wire-level state
  during a handshake and is what zgrab2 / sshamble consume today.
* [`crypto/ssl2`](crypto/ssl2) implements the obsolete **SSL 2.0** protocol
  (Hickman 1995, deprecated by RFC 6176) end-to-end: client `Probe` and
  full `Handshake`, RSA-encrypted master key exchange, MD5 record MACs,
  and bulk encryption with RC4-128, RC2-128 (incl. 40-bit export),
  DES-CBC, and 3DES-EDE-CBC. A matching `Server` type accepts CLIENT-HELLO
  messages, runs the full handshake, and exposes the resulting connection
  via `Read` / `Write`. Intended exclusively for security testing,
  inventory, and DROWN-style research against legacy systems — see the
  package doc.
* [`crypto/ssl3/cryptobyte`](crypto/ssl3/cryptobyte) is a frozen-API copy of
  cryptobyte for use by the SSL 3 stack so the legacy code is decoupled
  from upstream API churn.

### Certificate Transparency and JSON helpers

* [`crypto/x509/ct`](crypto/x509/ct) is the ZCrypto fork of Google's CT
  library, kept in-tree and integrated with the fork's `Certificate` type.
* [`crypto/json`](crypto/json) provides JSON marshalers for crypto types
  (DH/DHE/ECDHE parameters, RSA public keys, etc.) used by zgrab2-style
  scanners.

### `golang.org/x/crypto` integration

The `x/crypto` tree is vendored under [`x/crypto`](x/crypto) and tracked
against [`refs/xcrypto.hash`](refs/xcrypto.hash). It is rewritten so all
imports resolve through the fork's module path. SSH-research helpers and
struct fields needed by sshamble are layered on top.

### Internal plumbing changes

These are not user-facing features, but explain why test output and runtime
behavior may differ from upstream Go:

* `crypto/internal/fips140*` is configured so non-FIPS mode never gates
  weak primitives. The `cryptocustomrand` and similar GODEBUGs are stubbed
  to behave permissively out-of-tree.
* `internal/godebug` re-reads `$GODEBUG` on every `Setting.Value()` call so
  `t.Setenv` works in tests run from a third-party module path.
* `crypto/subtle` provides linkname stubs for the FIPS DIT helpers
  (`setDITEnabled`/`setDITDisabled`) since the runtime hooks they target
  do not exist outside the standard library.
* `crypto/x509.CreateCertificate` auto-generates a 20-octet random
  `SerialNumber` when `template.SerialNumber == nil`, matching ZCrypto.
* `pkix.Name` preserves both regular DN attributes and `ExtraNames` during
  marshaling so round-tripped certs keep the original RDN sequence.

## Components at a glance

| Package                                 | Origin & purpose                                     |
| --------------------------------------- | ---------------------------------------------------- |
| [`crypto/...`](crypto)                  | Modern Go crypto, with weak-primitive gates removed  |
| [`crypto/tls`](crypto/tls)              | Modern TLS 1.0–1.3 with permissive sig schemes       |
| [`crypto/ssl3/tls`](crypto/ssl3/tls)    | Legacy SSL 3.0 / TLS 1.0–1.2 with `HandshakeLog`     |
| [`crypto/ssl2`](crypto/ssl2)            | Obsolete SSL 2.0 client + server (research only)     |
| [`crypto/ssl3/rc2`](crypto/ssl3/rc2)    | RC2 block cipher (40/56/64/128-bit)                  |
| [`crypto/x509`](crypto/x509)            | ZCrypto-style permissive parser + 3-set `Verify()`   |
| [`crypto/x509/ct`](crypto/x509/ct)      | ZCrypto fork of Google CT                            |
| [`crypto/json`](crypto/json)            | JSON marshalers for scanner output                   |
| [`encoding/asn1`](encoding/asn1)        | ZCrypto-style permissive ASN.1                       |
| [`x/crypto`](x/crypto)                  | `golang.org/x/crypto` vendored + research extensions |

## Documentation

Documentation uses Godoc. See https://godoc.org/github.com/runZeroInc/excrypto/

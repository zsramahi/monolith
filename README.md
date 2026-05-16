# Monolith

A post-quantum authenticated cipher with both symmetric and public-key modes, packaged as a single Windows binary.

## Overview

- **Symmetric mode** — fast file encryption with a shared 256-bit key, built on an original ARX duplex-sponge construction.
- **Asymmetric mode** — public-key encryption via ML-KEM-1024 (NIST Level 5 post-quantum KEM), with PEM-wrapped keypairs.

Both modes produce authenticated `.mono` files with built-in tamper detection. One executable, no runtime dependencies.

## Install

Download `monolith.exe` from [Releases](https://github.com/zsramahi/monolith/releases) and place it on your `PATH`.

## Usage

Symmetric:

```
monolith genkey --out my.key
monolith encrypt secret.txt --key my.key
monolith decrypt secret.txt.mono --key my.key
```

Public-key:

```
monolith genkeypair --out-public bob.pub --out-secret bob.priv
monolith encrypt secret.txt --to bob.pub
monolith decrypt secret.txt.mono --secret bob.priv
```

Additional commands: `inspect`, `selftest`, `version`, `help`.

## Build

Requires `gcc` (mingw-w64) on Windows.

```
build.bat
```

Output: `bin/monolith.exe`.

## Status

Not third-party reviewed. For production secrets, use vetted tools such as age, GPG, or libsodium.

## Attribution

KEM math (`src/kem/keccak.c`, `poly.c`, `indcpa.c`, `kem.c`) is adapted from the public-domain CRYSTALS-Kyber reference (CC0 / Apache 2.0).

# Sealbook

<img src="Logo.png" width="200" alt="Sealbook logo">

Sealbook is a fully end-to-end encrypted vault for your contacts, calendars and notes, built to be self-hosted. Your data is encrypted on your device and the server only ever sees ciphertext. It cannot read your data, and neither can anyone who takes a copy of its database.

This project exists because the usual options don't offer this. CalDAV and CardDAV servers store your address book in the clear, and hand your provider everyone you know. Sealbook uses its own protocol instead, designed security-first and *resistant* to future quantum attack.

> [!IMPORTANT]
> This repository is the **server** and the **CLI**. To use Sealbook from a phone
> or browser you also need a client: [sealbook-web](https://github.com/silent-sphinx/sealbook-web)
> or [sealbook-android](https://github.com/silent-sphinx/sealbook-android).

> [!WARNING]
> Sealbook is in early development and is not ready to be your only copy of
> anything. Keep a backup of your data elsewhere.

## Contents

- [Sealbook](#sealbook)
  - [Contents](#contents)
  - [Deploy with Docker](#deploy-with-docker)
  - [Certificates](#certificates)
    - [`self-signed` - home network, VPN, or bare IP](#self-signed---home-network-vpn-or-bare-ip)
    - [`provided` - you have a public domain name](#provided---you-have-a-public-domain-name)
    - [`proxy` - behind a reverse proxy](#proxy---behind-a-reverse-proxy)
  - [Configuration](#configuration)
    - [The ones you'll actually touch](#the-ones-youll-actually-touch)
    - [The rest](#the-rest)
  - [Storage limits](#storage-limits)
  - [Behind a reverse proxy](#behind-a-reverse-proxy)
  - [Backups](#backups)
  - [Running from source](#running-from-source)
  - [Clients](#clients)

## Deploy with Docker

A `docker-compose.yml` is available in this repository. Follow the steps below to deploy Sealbook on your docker instance.

**1. Clone the Repo & Build the image.**

```bash
git clone https://github.com/silent-sphinx/sealbook.git
cd sealbook
docker build -t sealbook:local .
```

**2. TLS Configuration (IMPORTANT).** 

Sealbook will ALWAYS use TLS, this is a necessary step to ensure that all communication between the server and client is fully encrypted.

There are 3 TLS configuration methods available:

- `self-signed` certificate (Raw IP, Direct Access on IP)
- `provided` - provide certificate files (Custom Domain directly exposed)
- `reverse-proxy` - Cloudflare Tunnel, Tailscale, Nginx, Apache2 Proxy

The shipped `SEALBOOK_TLS_MODE: self-signed`
is right for a home network, a VPN, or access by bare IP. Set
`SEALBOOK_TLS_SANS` to the hostname or IP address your clients will use, or the
certificate will only be valid for `localhost`. If you have a public domain name
or a reverse proxy, change the mode instead. See
[Certificates](#certificates).

**3. Review the Docker Compose file** 

If you intend to use `sealbook-web` as your client then ensure that `SEALBOOK_CORS_ORIGINS` is set to the domain name, or IP Address you will access sealbook on.

For a full list of parameters check [Configuration](#configuration).

**4. Start it.**

```bash
docker compose up -d
docker compose logs -f
```

You're looking for:

```text
sealbook listening on https://0.0.0.0:8443 (TLS 1.3, X25519MLKEM768 preferred)
```

Now point a client at `https://your-host:8443` and register an account. The
host in that URL has to be one `SEALBOOK_TLS_SANS` covers: clients verify it
against the certificate even when they pin the certificate, so anything else
fails the handshake with a name mismatch.

> [!IMPORTANT]
> Registration is open. There is no invite system and no way to close signups, so anyone who can reach the port can create an account. If you're exposing Sealbook to the internet for yourself, put it behind a VPN, or firewall the port to the addresses you use.

Your data lives in the `sealbook-data` Docker volume. See [Backups](#backups) before you rely on it.

## Certificates

Sealbook always requires TLS there is no plaintext HTTP mode. Tell it where its certificate comes from with `SEALBOOK_TLS_MODE`, which is already in `docker-compose.yml`.

| `SEALBOOK_TLS_MODE` | Use it when | Who holds the certificate clients check |
| --- | --- | --- |
| `self-signed` | Home network, VPN, or access by bare IP | Sealbook. Clients pin it. |
| `provided` | You have a public domain name | You, from Let's Encrypt or your own CA |
| `proxy` | Something else already terminates TLS for you | Your reverse proxy |

Sealbook looks for exactly two files, `cert.pem` and `key.pem`, in the `tls`
subdirectory of its data directory (so `/data/tls/` by default).

### `self-signed` - home network, VPN, or bare IP

This is the shipped default. There's no public name to certify, so Sealbook
generates its own certificate on first start and keeps it. Clients pin it, which
is what makes this safe rather than a downgrade.

Tell it which addresses you'll reach it on. Pinning a certificate does not skip
the name check, so a certificate that doesn't name the host in the client's URL
is refused:

```yaml
environment:
  SEALBOOK_TLS_MODE: self-signed
  SEALBOOK_TLS_SANS: sealbook.lan,10.88.42.134
```

A comma-separated list of hostnames and IP addresses, with no scheme, port or
prefix length. `localhost`, `127.0.0.1`, `0.0.0.0` and `10.0.2.2` (the Android
emulator's alias for its host) are always included. Change the list and the
certificate is regenerated on the next start, so clients have to pin the new
one; the log says when that has happened.

On startup it prints the names it covers and the fingerprint, so you can check
what your client is seeing:

```text
INFO sealbook_server: clients must pin this certificate (sha256)
  fingerprint=86:FF:BF:04:9F:4D:8E:D6:2A:CE:63:37:85:CA:3E:55:88:F0:EC:1B:...
INFO sealbook_server: certificate covers these names; add yours with SEALBOOK_TLS_SANS
  names=0.0.0.0, 10.0.2.2, 10.88.42.134, 127.0.0.1, localhost, sealbook.lan
```

That is the same value `openssl x509 -fingerprint -sha256` prints. Copy the
certificate out to hand to your clients:

```bash
docker compose cp sealbook:/data/tls/cert.pem ./cert.pem
```

### `provided` - you have a public domain name

Get a certificate however you normally would and bind-mount the two files into
place. In `docker-compose.yml`:

```yaml
environment:
  SEALBOOK_TLS_MODE: provided
volumes:
  - sealbook-data:/data
  - /etc/letsencrypt/live/sealbook.example.com/fullchain.pem:/data/tls/cert.pem:ro
  - /etc/letsencrypt/live/sealbook.example.com/privkey.pem:/data/tls/key.pem:ro
```

This mode never generates a certificate. If the files aren't there it refuses to start.

Sealbook reads the certificate once at startup, so restart it after every
renewal:

```bash
docker compose restart sealbook
```

### `proxy` - behind a reverse proxy

Your proxy holds the certificate clients check. Sealbook still speaks TLS on the
hop from the proxy, because it has no plaintext mode, but that certificate is
only between the two of them, so it generates one and no CA is involved.

```yaml
environment:
  SEALBOOK_TLS_MODE: proxy
  SEALBOOK_TRUSTED_PROXIES: "10.0.0.0/8"
```

Set `SEALBOOK_TRUSTED_PROXIES` as well, Sealbook warns at startup if you don't, because without it every request looks like it came from the proxy and the whole deployment shares one rate limit. See [Behind a reverse
proxy](#behind-a-reverse-proxy).

## Configuration

Everything is set through environment variables in `docker-compose.yml`.

### The ones you'll actually touch

| Variable | Default | What it does |
| --- | --- | --- |
| `SEALBOOK_ENV` | unset | Set to `production` for any real deployment. Stops trusting localhost dev origins, and stops writing `cert.pem` into the working directory. |
| `SEALBOOK_TLS_MODE` | `provided` in production, else `self-signed` | Where the certificate comes from: `self-signed`, `provided` or `proxy`. See [Certificates](#certificates). |
| `SEALBOOK_TLS_SANS` | `localhost`, `127.0.0.1`, `0.0.0.0`, `10.0.2.2` | Hostnames and IP addresses a generated certificate is valid for, comma-separated. Set this in `self-signed` mode to whatever your clients put in their URL. |
| `SEALBOOK_CORS_ORIGINS` | localhost dev ports | Comma-separated addresses your web client is served from. Browsers block anything not listed. |
| `SEALBOOK_DATA_DIR` | `/data` | Where the database and certificates live. This is the directory to back up. |
| `SEALBOOK_BIND` | `0.0.0.0:8443` | Address and port to listen on inside the container. |

### The rest

| Variable | Default | What it does |
| --- | --- | --- |
| `SEALBOOK_TLS_DIR` | `<data dir>/tls` | Certificate directory, if you want it somewhere other than beside the database. |
| `SEALBOOK_DB` | `<data dir>/sealbook.db` | Database file, if you want it elsewhere. |
| `SEALBOOK_CERT_EXPORT` | unset | Write a copy of the certificate here on start, for clients that need to pin it. |
| `SEALBOOK_TRUSTED_PROXIES` | unset | Proxies whose `X-Forwarded-For` you believe, see [below](#behind-a-reverse-proxy). |
| `SEALBOOK_MAX_OBJECTS` | `50000` | Most objects one account may store: contacts, events, notes, and the address books, calendars and notebooks holding them. |
| `SEALBOOK_MAX_BYTES` | `134217728` | Most stored bytes one account may use (128 MiB of padded ciphertext). |
| `SEALBOOK_MAX_ROTATION_BODY` | `268435456` | Largest key-rotation request (256 MiB). See [Storage limits](#storage-limits) before changing it. |
| `SEALBOOK_REVISION_RETENTION_DAYS` | `30` | How long a deleted object's tombstone has to be kept: a key rotation retires the ones older than this, so a longer window means deletions take longer to reclaim their quota. |
| `SEALBOOK_FULL_INTEGRITY_CHECK` | unset | Set to `1` for an exhaustive SQLite check at startup instead of the quick one. Worth it after a crash or a restore. |
| `RUST_LOG` | unset | Log level. `sealbook_server=info` is a good default; `=debug` when something is wrong. |

## Storage limits

Three settings interact, and one of them is the real ceiling.

Revoking a device has to make the old collection key useless, so it re-encrypts
the whole vault under a new one. Only a client can do that, since only a client
can decrypt, so the re-encrypted vault arrives as **one request** —
`SEALBOOK_MAX_ROTATION_BODY`. A vault that has outgrown that body cannot be
rotated, and a rotation that cannot be sent means a revoked device keeps a key
that still opens everything it ever synced.

So the server refuses a write that would push a vault past what one rotation can
carry, rather than letting it grow and discovering the problem at revocation
time. In practice that, not `SEALBOOK_MAX_BYTES`, is what you hit first. The
effective ceiling is logged at startup:

```
INFO storage limits max_objects=50000 max_bytes=134217728
     max_rotation_body=268435456 rotatable_bytes=201228272
```

If you raise `SEALBOOK_MAX_BYTES`, raise `SEALBOOK_MAX_ROTATION_BODY` with it —
roughly four thirds of the byte quota, plus about 320 bytes per object, since the
body is base64 JSON. Two rotations may be in flight at once and each is buffered
and parsed whole, so that setting is the server's peak memory, not a free number.

A single object is capped at 8 MiB of padded plaintext, which is the ceiling a
long note runs into first. Padding rounds up to a power of two, so the usable
ceiling for one object's contents is just under 8 MiB, and 16 objects at that
size would fill a default account.

An account may have 16 devices enrolled at once. Every device gets a wrap of the
collection key in every rotation, so the list is bounded; revoking a device frees
its slot.

## Behind a reverse proxy

You don't need a proxy, Sealbook terminates its own TLS and can face the
internet directly. If you use one anyway, two things matter.

**The proxy must speak Sealbook's TLS to the backend.** Do not forward plaintext HTTP to it. Your proxy has to support `X25519MLKEM768`; many don't.

**Tell Sealbook about the proxy, or rate limiting breaks.** 

Limits are keyed on the caller's address, which Sealbook reads from the TCP connection. Behind a proxy every request appears to come from the proxy, so the whole deployment shares a single bucket and one noisy user locks out everyone. Name the proxy and its `X-Forwarded-For` header is believed instead:

```yaml
SEALBOOK_TRUSTED_PROXIES: "10.0.0.0/8, 2001:db8::/32"
```

> [!CAUTION]
> Leave this unset if clients connect directly. An entry like `0.0.0.0/0` lets
> any caller claim any address and defeats rate limiting completely.

## Backups

**Back up the whole data directory, not just the database.** It holds the
database *and* the TLS material, and they belong together, the database alone is useless to a client that pinned this server's certificate.

Two scripts do this properly, and are meant to be run from cron:

```bash
# Back up, keeping the 14 most recent. Safe to run against a live server.
./scripts/sealbook-backup.sh /sealbook /sealbook-backups 14

# Restore-test a backup by starting a real server against a copy of it.
./scripts/sealbook-verify-backup.sh /sealbook-backups/sealbook-20260101T040000Z
```

`sealbook-backup.sh` uses SQLite's online backup, folds the write-ahead log into the copy so each backup is one self-contained file, runs an integrity check, copies the TLS directory alongside it, and prunes old backups past the retention count.

`sealbook-verify-backup.sh` copies a backup to a scratch directory, starts a server against it on a spare port, and probes it which catches a database that opens but whose schema this build rejects, or missing TLS material. 

If you'd rather not use the scripts:

```bash
mkdir -p /sealbook-backups
sqlite3 /sealbook/sealbook.db \
  ".backup '/sealbook-backups/sealbook-$(date -u +%Y%m%dT%H%M%SZ).db'"
cp -a /sealbook/tls /sealbook-backups/
```

> [!WARNING]
> Don't copy `sealbook.db` with `cp` while the server is running. SQLite keeps newer committed pages in its `-wal` file and you will get a torn backup.

## Running from source

You need a recent stable Rust toolchain.

```bash
cargo run -p sealbook-server
```

It listens on `https://127.0.0.1:8443`, creates `sealbook.db` and a `tls/`
directory in the working directory, and writes a copy of its self-signed
certificate to `./cert.pem`, which is where the CLI looks by default, so the two work together with no setup.

This is development mode: `SEALBOOK_ENV` is unset, so localhost origins are allowed and the certificate is generated for you. Don't run a real deployment this way.

## Clients

Sealbook needs a client to be useful day to day.

| Platform | Status | Repository |
| -------- | ------ | ---------- |
| CLI | Active development | [sealbook](https://github.com/silent-sphinx/sealbook) (in this repository) |
| Web | Active development | [sealbook-web](https://github.com/silent-sphinx/sealbook-web) |
| Android | Active development | [sealbook-android](https://github.com/silent-sphinx/sealbook-android) |
| iOS | Planned | — |
| Desktop | Planned | — |

# Sealbook

<img src="Logo.png" width="200" alt="Sealbook logo">

Sealbook is a fully end-to-end encrypted vault for your contacts, calendars,
notes and bookmarks, built to be self-hosted. Your data is encrypted on your
device and the server only ever sees ciphertext.

> [!IMPORTANT]
> This repository is the **server** and the **CLI**. To use Sealbook from a
> phone or browser you also need a client: [sealbook-web](https://github.com/silent-sphinx/sealbook-web)
> or [sealbook-android](https://github.com/silent-sphinx/sealbook-android).

> [!WARNING]
> Sealbook is in early development and is not ready to be your only copy of
> anything. Keep a backup of your data elsewhere.

## Getting started

### Run with Docker

```bash
git clone https://github.com/silent-sphinx/sealbook.git
cd sealbook
docker build -t sealbook:local .
docker compose up -d
```

### TLS certificates

Sealbook always uses TLS. The Docker setup defaults to a self-signed certificate
for local or VPN use; set `SEALBOOK_TLS_SANS` to the hostname or IP address your
clients will use.

For a public domain, supplied certificate, or reverse proxy, see
[Certificates](https://github.com/silent-sphinx/sealbook/wiki/Deployment-and-Configuration#certificates).

### Registration

Registration is open by default. After the required accounts have signed up, set
`SEALBOOK_DISABLE_REGISTRATION: 1` and restart the server.

## Clients

This repository is just a server, with a built-in CLI, day-to-day users will prefer the use of a client, choose one of the following below.

Sealbook-Web will soon be decomissioned, this is because web browsers are inherently insecure compared to dedicated OS application.

| Platform | Status | Repository |
| --- | --- | --- |
| CLI | Active development | This repository |
| Desktop (Windows/Mac OS/Linux) | Active Development | [sealbook-desktop](https://github.com/silent-sphinx/sealbook-desktop) |
| Web | To be decomissioned | [sealbook-web](https://github.com/silent-sphinx/sealbook-web) |
| Android | Active development | [sealbook-android](https://github.com/silent-sphinx/sealbook-android) |
| iOS | Planned | - |

## Security

The [threat model](https://github.com/silent-sphinx/sealbook/wiki/Threat-Model)
is the thing to read before you trust this with anything: what the server can
and cannot do, what it learns anyway, and what your password and recovery phrase
are each worth.

## Documentation

### Running a server

- [Deployment and configuration](https://github.com/silent-sphinx/sealbook/wiki/Deployment-and-Configuration) - Docker, TLS, environment variables, storage limits, reverse proxies, backups, and running from source.
- [Self-hosting with Tailscale](https://github.com/silent-sphinx/sealbook/wiki/Self%E2%80%90Hosting-Sealbook) - exposing Sealbook through Tailscale without terminating its TLS.

### Trust and privacy

- [Threat model](https://github.com/silent-sphinx/sealbook/wiki/Threat-Model) - what the server can and cannot do, what it learns, and what your password and recovery phrase are worth.

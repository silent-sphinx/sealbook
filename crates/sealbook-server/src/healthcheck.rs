//! Local liveness probe, used by the container `HEALTHCHECK`.
//!
//! A probe has to speak the same TLS as the listener, and the listener offers
//! only TLS 1.3 with `X25519MLKEM768`. Stock `curl` and `wget` on current base
//! images cannot negotiate that group, so an image health check built on them
//! reports a healthy server as unhealthy. This module does the handshake with
//! the same crypto provider the listener uses, which also means the probe fails
//! if the PQ group ever stops being available.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Checks that the server process on `bind` answers `GET /health`.
///
/// Returns an error, with the reason, if it does not.
pub fn run(bind: &str) -> anyhow::Result<()> {
    let addr = loopback_target(bind)?;
    let provider = Arc::new(crate::tls::pq_only_provider()?);
    let verifier = LoopbackVerifier {
        algorithms: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .context("tls versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let server_name = ServerName::try_from("localhost").context("server name")?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name.to_owned())
        .context("tls client connection")?;
    let mut socket =
        TcpStream::connect_timeout(&addr, TIMEOUT).with_context(|| format!("connect to {addr}"))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut tls = rustls::Stream::new(&mut connection, &mut socket);

    tls.write_all(
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nUser-Agent: sealbook-healthcheck\r\nConnection: close\r\n\r\n",
    )
    .context("send request")?;

    let mut response = Vec::new();
    // The server closes the connection after responding. A peer that closes
    // without a `close_notify` surfaces as an error here, which is not a failure
    // of the health check as long as a response arrived first.
    if let Err(error) = tls.read_to_end(&mut response) {
        if response.is_empty() {
            return Err(error).context("read response");
        }
    }

    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_default();
    if !status_line.starts_with("HTTP/1.1 200") {
        anyhow::bail!("unhealthy: {status_line:?}");
    }
    Ok(())
}

/// Resolves the listen address into something to probe on the loopback interface.
///
/// A wildcard bind (`0.0.0.0`, `::`) is reachable on loopback, so the port is
/// kept and the host replaced. Anything that does not end up on loopback is
/// refused, because this probe deliberately does not verify certificates.
fn loopback_target(bind: &str) -> anyhow::Result<SocketAddr> {
    let addr = bind
        .to_socket_addrs()
        .with_context(|| format!("parse bind address {bind}"))?
        .next()
        .with_context(|| format!("bind address {bind} resolved to nothing"))?;
    let addr = if addr.ip().is_unspecified() {
        match addr.ip() {
            IpAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], addr.port())),
            IpAddr::V6(_) => {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), addr.port())
            }
        }
    } else {
        addr
    };
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "health check probes loopback only, but {bind} resolves to {}; run it inside the \
             container or on the host that serves it",
            addr.ip()
        );
    }
    Ok(addr)
}

/// Accepts whatever certificate the local process presents.
///
/// This is sound only because the probe connects to loopback, sends no secret,
/// and reads nothing it trusts: it asserts that the process is alive and serving,
/// not that it is authentic. Verifying properly is not possible here — an
/// operator-supplied certificate names their domain, not `127.0.0.1`, so hostname
/// verification would fail on exactly the correctly configured deployments.
/// Signature checking is still delegated to the provider, so the handshake itself
/// is real.
#[derive(Debug)]
struct LoopbackVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for LoopbackVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_bind_is_probed_on_loopback() {
        let addr = loopback_target("0.0.0.0:8443").unwrap();
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 8443)));
        assert!(loopback_target("[::]:9000").unwrap().ip().is_loopback());
        assert_eq!(
            loopback_target("127.0.0.1:1234").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 1234))
        );
    }

    #[test]
    fn a_remote_bind_is_refused_rather_than_probed_without_verification() {
        assert!(loopback_target("93.184.216.34:8443").is_err());
    }
}

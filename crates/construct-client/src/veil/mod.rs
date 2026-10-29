//! VEIL on this client: Konstruct reached through a veil-front relay, as iOS reaches it
//! (construct-docs decisions/desktop-veil.md).
//!
//! The TLS to the front is construct-veil's, pinned to the front's key; its ClientHello is
//! Chrome's, byte for byte ([`chrome_hello`], through the rustls fork's `client_hello_rewriter`).
//! On iOS the system builds the hello and it is Safari's; here the largest crowd is Chrome.

pub mod chrome_hello;
pub mod redact;
pub mod transport_route;
pub mod trust;
pub mod tunnel;

use std::sync::Arc;

/// Every veil-front connection from now on sends Chrome's hello (a fresh shape per connection,
/// as Chrome shuffles its extensions per connection).
pub fn install_chrome_hello() {
    construct_veil::set_tls_client_hook(Some(Arc::new(shape_like_chrome)));
}

fn shape_like_chrome(config: &mut rustls::ClientConfig) {
    // Chrome offers `h2, http/1.1` on every HTTPS connection; veil-front asks for `h2` alone,
    // which JA4 does not see (it keeps only the first protocol) but the list on the wire does.
    // The front still picks h2; were it to pick http/1.1, the h2 handshake would fail aloud.
    if config.alpn_protocols == [b"h2".to_vec()] {
        config.alpn_protocols.push(b"http/1.1".to_vec());
    }
    config.client_hello_rewriter = Some(Arc::new(chrome_hello::ChromeHello::new(
        chrome_hello::Profile::Chrome155,
    )));
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    /// JA4 of a fresh Chrome 155 hello, from a live capture (see `chrome_hello`'s tests).
    const CHROME_155_JA4: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";

    /// What construct-veil dials with, as far as the hello goes: aws-lc-rs with the hybrid
    /// post-quantum group first, ALPN h2 — then this client's hook.
    fn client(cert: &CertificateDer<'static>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        shape_like_chrome(&mut config);
        config
    }

    fn server(cert: CertificateDer<'static>, key: Vec<u8>) -> rustls::ServerConfig {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        config
    }

    /// On the wire the hello is Chrome 155's, and rustls still completes the handshake with an
    /// ordinary TLS 1.3 server: the extensions it only advertises are not selected, the key
    /// shares and the transcript are its own. What a front sees, without a front.
    #[test]
    fn the_hello_on_the_wire_is_chromes_and_the_handshake_completes() {
        let generated = rcgen::generate_simple_self_signed(vec!["front.example".into()]).unwrap();
        let cert = generated.cert.der().clone();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client(&cert)),
            ServerName::try_from("front.example").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server(
            cert,
            generated.key_pair.serialize_der(),
        )))
        .unwrap();

        let mut first_flight = Vec::new();
        client.write_tls(&mut first_flight).unwrap();
        // One handshake record: a 5-byte record header, then the ClientHello message.
        assert_eq!(first_flight[0], 0x16, "a handshake record");
        let hello = &first_flight[5..];
        assert_eq!(
            chrome_hello::ja4(hello).as_deref(),
            Some(CHROME_155_JA4),
            "the hello on the wire"
        );
        // Chrome's ALPN list, as a live Chrome 155 capture has it (JA4 keeps only `h2`).
        let parsed = chrome_hello::ParsedHello::parse(hello).expect("a hello");
        assert_eq!(
            parsed.extension(0x0010), // ALPN
            Some(&b"\x00\x0c\x02h2\x08http/1.1"[..]),
            "ALPN h2, http/1.1"
        );

        server.read_tls(&mut &first_flight[..]).unwrap();
        server.process_new_packets().unwrap();
        for _ in 0..10 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets().unwrap();
        }
        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "handshake done"
        );
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    }

    /// Without the hook the hello is rustls's own — the test above is about the hook.
    #[test]
    fn without_the_rewriter_the_hello_is_not_chromes() {
        let generated = rcgen::generate_simple_self_signed(vec!["front.example".into()]).unwrap();
        let mut config = client(generated.cert.der());
        config.client_hello_rewriter = None;
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("front.example").unwrap(),
        )
        .unwrap();
        let mut first_flight = Vec::new();
        client.write_tls(&mut first_flight).unwrap();
        assert_ne!(
            chrome_hello::ja4(&first_flight[5..]).as_deref(),
            Some(CHROME_155_JA4)
        );
    }
}

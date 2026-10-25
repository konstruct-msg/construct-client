//! The local network as history moves over it, the way iOS moves it (`HistoryNearbyChannel`):
//! the sending device advertises `_construct-transfer._tcp` under a name both devices compute from
//! the account and the receiving device (`history::discovery`), and takes one connection; the
//! receiving device looks that name up and connects. Plain TCP — what crosses it is the core's
//! signed handshake and sealed chunks, so the network is not trusted with anything.
//!
//! Only IPv4: a phone on the same Wi-Fi reaches it, and an address the other side cannot route
//! is never advertised.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::net::{TcpListener, TcpStream};

/// The service iOS advertises and browses (`NearbyTransferService.serviceType`).
pub(crate) const SERVICE_TYPE: &str = "_construct-transfer._tcp.local.";

/// The length of the service name in [`SERVICE_TYPE`], without its underscore.
const SERVICE_NAME_LEN: u8 = 18;

/// How long either side waits for the other to appear.
pub(crate) const WAIT: Duration = Duration::from_secs(5 * 60);

fn mdns(e: mdns_sd::Error) -> String {
    format!("local network: {e}")
}

/// The mDNS responder's thread, stopped when this is dropped — also when the task holding it is
/// cancelled — which the daemon does not do by itself.
struct Daemon(ServiceDaemon);

impl Daemon {
    fn start() -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(mdns)?;
        daemon.disable_interface(IfKind::IPv6).map_err(mdns)?;
        // "construct-transfer" is 18 characters, over RFC 6763's 15. Bonjour takes it, and the
        // daemon would otherwise refuse to register it — in its log only.
        daemon
            .set_service_name_len_max(SERVICE_NAME_LEN)
            .map_err(mdns)?;
        Ok(Self(daemon))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// A name on the local network, answered until this is dropped.
pub(crate) struct Advertised {
    daemon: Daemon,
    fullname: String,
    listener: TcpListener,
}

/// Listen on a free port and advertise it as `instance`. The host name is made of the instance
/// too, so the network learns nothing it did not already: no device name, no account.
pub(crate) async fn advertise(instance: &str) -> Result<Advertised, String> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| format!("local network: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local network: {e}"))?
        .port();
    let daemon = Daemon::start()?;
    let host = format!("konstruct-{}.local.", &instance[..8.min(instance.len())]);
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        instance,
        &host,
        "",
        port,
        None::<std::collections::HashMap<String, String>>,
    )
    .map_err(mdns)?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.0.register(info).map_err(mdns)?;
    Ok(Advertised {
        daemon,
        fullname,
        listener,
    })
}

impl Advertised {
    /// The first device to connect, within [`WAIT`].
    pub(crate) async fn accept(&self) -> Result<TcpStream, String> {
        match tokio::time::timeout(WAIT, self.listener.accept()).await {
            Ok(Ok((stream, from))) => {
                tracing::info!(%from, "history: the other device connected");
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
            Ok(Err(e)) => Err(format!("local network: {e}")),
            Err(_) => Err("the other device did not connect".into()),
        }
    }
}

impl Drop for Advertised {
    fn drop(&mut self) {
        // The goodbye is sent by the daemon's thread; give it a moment before it stops.
        if let Ok(done) = self.daemon.0.unregister(&self.fullname) {
            let _ = done.recv_timeout(Duration::from_millis(300));
        }
    }
}

/// Find `instance` on the local network and connect to it, within [`WAIT`].
pub(crate) async fn connect(instance: &str) -> Result<TcpStream, String> {
    let daemon = Daemon::start()?;
    let found = tokio::time::timeout(WAIT, find(&daemon.0, instance)).await;
    drop(daemon);
    let addrs = match found {
        Ok(addrs) => addrs?,
        Err(_) => return Err("the other device was not found on this network".into()),
    };
    let mut last = String::from("the other device was not reachable");
    for addr in addrs {
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                tracing::info!(%addr, "history: connected to the other device");
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => last = format!("local network: {addr}: {e}"),
            Err(_) => last = format!("local network: {addr}: no answer"),
        }
    }
    Err(last)
}

async fn find(daemon: &ServiceDaemon, instance: &str) -> Result<Vec<SocketAddr>, String> {
    let events = daemon.browse(SERVICE_TYPE).map_err(mdns)?;
    let wanted = format!("{instance}.{SERVICE_TYPE}");
    loop {
        let event = events
            .recv_async()
            .await
            .map_err(|_| "local network: the search stopped".to_string())?;
        if let ServiceEvent::ServiceResolved(service) = event
            && service.fullname.eq_ignore_ascii_case(&wanted)
        {
            let addrs: Vec<SocketAddr> = service
                .get_addresses_v4()
                .into_iter()
                .map(|ip| SocketAddr::from((ip, service.port)))
                .collect();
            if !addrs.is_empty() {
                return Ok(addrs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Over the machine's own network: what one side advertises, the other finds by name. Another
    /// device's name, on the network first, is not what it connects to.
    #[tokio::test]
    async fn an_advertised_name_is_found_and_connected_to() {
        tokio::time::timeout(Duration::from_secs(30), found_and_connected())
            .await
            .expect("the device advertising the name answered");
    }

    /// Answer the first connection with `word`.
    async fn answering(name: &str, word: &'static [u8]) -> tokio::task::JoinHandle<()> {
        let ad = advertise(name).await.expect("advertise");
        tokio::spawn(async move {
            let mut s = ad.accept().await.expect("accept");
            s.write_all(word).await.unwrap();
            // Held until the reader is done, so the name stays on the network.
            let _ = s.read(&mut [0u8; 1]).await;
        })
    }

    async fn found_and_connected() {
        let name = format!("{:032x}", rand::random::<u128>());
        let other = format!("{:032x}", rand::random::<u128>());
        let decoy = answering(&other, b"no").await;
        let looking = tokio::spawn({
            let name = name.clone();
            async move { connect(&name).await.expect("found by name") }
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        let device = answering(&name, b"ok").await;
        let mut stream = looking.await.unwrap();
        let mut back = [0u8; 2];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(
            &back, b"ok",
            "connected to the device that advertised the name"
        );
        drop(stream);
        device.await.unwrap();
        decoy.abort();
    }
}

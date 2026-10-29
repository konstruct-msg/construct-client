//! Fronts and IP addresses kept out of the logs (decisions/veil-front-in-logs-is-a-keyed-label):
//! in a release build a front's name and any IP address but loopback become `front#xxxxxxxx` /
//! `ip#xxxxxxxx` — 4 bytes of HMAC-SHA256 under a random key of this device. A log sent from one
//! device names each front by one label, so it still tells what happened; it gives no address to
//! block, and labels from two devices do not match. A debug build writes names as they are.
//!
//! The front shell's log writer passes every line through [`redact`]; names are registered here
//! as fronts become known (`client::veil`).

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{OnceLock, RwLock};

use hmac::{Hmac, Mac};
use sha2::Sha256;

static KEY: OnceLock<[u8; 32]> = OnceLock::new();
static NAMES: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Whether names are replaced: always in a release build.
fn active() -> bool {
    !cfg!(debug_assertions)
}

/// Use the key kept in `dir` (made there the first time; never leaves the device). Without a
/// call, a key made for this run is used.
pub fn init(dir: &Path) {
    let path = dir.join("log-label.key");
    let key = std::fs::read(&path)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
        .unwrap_or_else(|| {
            let key = rand::random::<[u8; 32]>();
            if let Err(e) = write_private(&path, &key) {
                eprintln!("log label key not kept: {e}");
            }
            key
        });
    let _ = KEY.set(key);
}

fn write_private(path: &Path, key: &[u8; 32]) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(path)?, key)
}

fn key() -> &'static [u8; 32] {
    KEY.get_or_init(rand::random)
}

fn label(kind: &str, name: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key()).expect("any key length");
    mac.update(name.to_ascii_lowercase().as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{kind}#{}", hex::encode(&tag[..4]))
}

/// A front's name, as logs and screens may show it.
pub fn front_label(name: &str) -> String {
    if active() {
        label("front", name)
    } else {
        name.to_owned()
    }
}

/// Names to replace from now on: a front's host and its SNI (in `host:port` the port stays).
pub fn register(names: impl IntoIterator<Item = impl Into<String>>) {
    let mut held = NAMES.write().unwrap_or_else(|e| e.into_inner());
    for name in names {
        let name: String = name.into();
        if !name.is_empty() && !held.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            held.push(name);
        }
    }
    // Longest first, so a name inside a longer one is not cut out of it.
    held.sort_by_key(|n| std::cmp::Reverse(n.len()));
}

/// `text` with every registered name and every IP address but loopback replaced.
pub fn redact(text: &str) -> Cow<'_, str> {
    if !active() {
        return Cow::Borrowed(text);
    }
    redact_always(text)
}

fn redact_always(text: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(text);
    for name in NAMES.read().unwrap_or_else(|e| e.into_inner()).iter() {
        if contains_ignore_case(&out, name) {
            out = Cow::Owned(replace_ignore_case(&out, name, &label("front", name)));
        }
    }
    match addresses(&out) {
        Some(replaced) => Cow::Owned(replaced),
        None => out,
    }
}

fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn replace_ignore_case(hay: &str, needle: &str, with: &str) -> String {
    let lower = hay.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(&needle) {
        out.push_str(&hay[at..at + i]);
        out.push_str(with);
        at += i + needle.len();
    }
    out.push_str(&hay[at..]);
    out
}

/// IP addresses in `text`, but loopback and unspecified, replaced by labels; `None` when there
/// are none. A candidate is a run of hex digits, dots and colons parsed strictly, so times
/// (`12:34:56`) and MAC addresses are left alone.
fn addresses(text: &str) -> Option<String> {
    let is_part = |c: char| c.is_ascii_hexdigit() || c == '.' || c == ':';
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut rest = text;
    while let Some(start) = rest.find(is_part) {
        out.push_str(&rest[..start]);
        let run = &rest[start..];
        let end = run.find(|c| !is_part(c)).unwrap_or(run.len());
        let token = &run[..end];
        match address_in(token) {
            Some((addr, len)) => {
                out.push_str(&label("ip", addr));
                out.push_str(&token[len..]);
                changed = true;
            }
            None => out.push_str(token),
        }
        rest = &run[end..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// An address at the start of `token` and its length: the whole token as IPv6, or IPv4 with an
/// optional `:port` after it.
fn address_in(token: &str) -> Option<(&str, usize)> {
    if let Ok(v6) = token.parse::<Ipv6Addr>() {
        return (!v6.is_loopback() && !v6.is_unspecified()).then_some((token, token.len()));
    }
    let v4 = token.split(':').next()?;
    let ip = v4.parse::<Ipv4Addr>().ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then_some((v4, v4.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A front's names and the addresses around them become labels, the same label each time;
    /// loopback, times and plain numbers stay.
    #[test]
    fn fronts_and_addresses_become_labels() {
        register(["front-test.example"]);
        let line = "VEIL tunnel up front=front-test.example:443 via Front-Test.example \
                    addr=203.0.113.7:443 local=127.0.0.1:60298 v6=2001:db8::1 at 12:34:56 port=443";
        let out = redact_always(line);
        assert!(
            !out.to_ascii_lowercase().contains("front-test.example"),
            "{out}"
        );
        assert!(
            !out.contains("203.0.113.7") && !out.contains("2001:db8::1"),
            "{out}"
        );
        assert!(
            out.contains("127.0.0.1:60298") && out.contains("12:34:56"),
            "{out}"
        );
        assert!(out.contains("port=443"));
        let front = label("front", "front-test.example");
        assert_eq!(out.matches(&front).count(), 2, "one label per front: {out}");
        assert!(out.contains(&format!("front={front}:443")), "{out}");
        assert!(
            out.contains(&format!("{}:443", label("ip", "203.0.113.7"))),
            "{out}"
        );
        // Stable within the device, so a log reads as one story.
        assert_eq!(
            redact_always("front-test.example"),
            redact_always("FRONT-TEST.example")
        );
    }

    #[test]
    fn a_line_without_names_is_not_copied() {
        assert!(matches!(
            redact_always("message stream connected"),
            Cow::Borrowed(_)
        ));
    }
}

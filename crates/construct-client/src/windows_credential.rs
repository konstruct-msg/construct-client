//! The store key's entry in Credential Manager, kept on this machine.
//!
//! `keyring` 3 writes `CRED_PERSIST_ENTERPRISE`: on an account with a roaming profile the entry
//! travels to every machine the person signs in to, while the store it opens stays here. The entry
//! is written with `CRED_PERSIST_LOCAL_MACHINE` instead; reading and deleting go through `keyring`,
//! which looks an entry up by its name whatever its persistence.

use anyhow::{Context, Result, bail};
use keyring::windows::WinCredential;
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW, CredWriteW,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn credential(entry: &keyring::Entry) -> Result<&WinCredential> {
    entry
        .get_credential()
        .downcast_ref()
        .context("not a Credential Manager entry")
}

/// Write the entry, replacing one of the same name (`CredWriteW` replaces it whole).
pub(crate) fn write(entry: &keyring::Entry, secret: &[u8]) -> Result<()> {
    let named = credential(entry)?;
    let mut target = wide(&named.target_name);
    let mut user = wide(&named.username);
    let mut blob = zeroize::Zeroizing::new(secret.to_vec());
    // SAFETY: all-zero is a valid CREDENTIALW (null pointers, zero counts).
    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = CRED_TYPE_GENERIC;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    cred.TargetName = target.as_mut_ptr();
    cred.UserName = user.as_mut_ptr();
    cred.CredentialBlobSize = blob.len().try_into()?;
    cred.CredentialBlob = blob.as_mut_ptr();
    // SAFETY: every pointer is to a buffer that outlives the call; strings end in a zero.
    if unsafe { CredWriteW(&cred, 0) } == 0 {
        bail!("CredWriteW: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the entry stays on this machine.
pub(crate) fn is_local(entry: &keyring::Entry) -> Result<bool> {
    let target = wide(&credential(entry)?.target_name);
    let mut found: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` ends in a zero; `found` is freed below when the call sets it.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) } == 0 {
        bail!("CredReadW: {}", std::io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `found` is one CREDENTIALW from the system's allocator.
    let persist = unsafe { (*found).Persist };
    // SAFETY: as above; not used after.
    unsafe { CredFree(found.cast()) };
    Ok(persist == CRED_PERSIST_LOCAL_MACHINE)
}

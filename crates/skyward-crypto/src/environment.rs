//! Make the secure world see the version of the system that made the keys.
//!
//! A key made under one build is refused by a key service that started while
//! a recovery's own, older build's version properties were set. Starting the
//! key service again, with those four values put back to the installed
//! system's own, is what Android's recovery does before it opens the data
//! partition. No key is renewed and nothing is written back: a key that is
//! still refused is left exactly as it was.

use anyhow::{Context, Result, ensure};
use std::time::{Duration, Instant};

/// The program behind the key service. Skyward starts this itself, from the
/// device's configuration, and supervises it: init has no service by this
/// name in a recovery, so `ctl.start` cannot bring it back. Killing the
/// process is what makes the supervisor start it again, reading the version
/// properties as they are now.
const KEYMINT_PROGRAM: &str = "/vendor/bin/hw/android.hardware.security.keymint-service-qti";

const BUILD_VERSION: [&str; 4] = [
    "ro.build.version.release",
    "ro.build.version.release_or_codename",
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
];

/// What the key service is being told, for a message that names the values
/// alongside the HAL's own answer.
pub fn said() -> String {
    BUILD_VERSION
        .iter()
        .map(|name| {
            format!(
                "{name}={}",
                skyward_sys::prop(name).unwrap_or_else(|| "(unset)".into())
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Which key service is running, as the hardware service names it.
pub fn hardware() -> String {
    let binder = match skyward_binder::driver::Binder::open() {
        Ok(binder) => binder,
        Err(e) => return format!("the key driver cannot be opened: {e:#}"),
    };
    match super::keymint::KeyMint::open(&binder).and_then(|service| service.hardware()) {
        Ok(h) => format!(
            "KeyMint {} at {:?}, {}",
            h.version, h.security_level, h.name
        ),
        Err(e) => format!("the key service does not answer about itself: {e:#}"),
    }
}

/// The process running `program`, found the way the recovery's own service
/// supervisor finds the ones it started: by the executable behind /proc.
fn running(path: &str) -> Option<u32> {
    std::fs::read_dir("/proc").ok()?.flatten().find_map(|e| {
        let pid: u32 = e.file_name().to_str()?.parse().ok()?;
        (std::fs::read_link(e.path().join("exe")).ok()? == std::path::Path::new(path))
            .then_some(pid)
    })
}

/// Make the key service read the installed system's version values, and wait
/// for it to be back. The values are read from the properties, which the
/// recovery set from the installed system's build.prop files before the
/// service first started. An empty value means the version was never adopted;
/// saying so beats letting the secure world answer a refusal no one can read.
///
/// The key service is one of this recovery's own programs, watched by the
/// supervisor that starts it again when it ends. Asking init to stop or start
/// it says the name is unknown: init has no such service in a recovery. End
/// the process instead; the supervisor brings it back with the values as
/// they stand now.
pub fn pin() -> Result<()> {
    for name in BUILD_VERSION {
        let value = skyward_sys::prop(name);
        ensure!(
            value.as_ref().is_some_and(|v| !v.is_empty()),
            "no value for {name} to give the key service: {}",
            said()
        );
        skyward_sys::kmsg(&format!(
            "key service environment: {name}={}",
            value.unwrap_or_default()
        ))?;
    }
    if let Some(pid) = running(KEYMINT_PROGRAM) {
        // Never signal this process. The search matches on the executable
        // behind /proc, and on this phone it once answered with the recovery
        // itself: the signal ended the recovery, the panel went black and the
        // supervisor started it again, with the partition left shut. Whatever
        // made the search answer that way, a process that cannot signal
        // itself cannot take the recovery down with it.
        let me = std::process::id();
        ensure!(
            pid != me,
            "the key service was looked for and this process ({me}) answered; refusing to end it"
        );
        skyward_sys::kmsg(&format!(
            "ending key service pid {pid} so it reads the installed system's version again"
        ))?;
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        ensure!(
            rc == 0,
            "signal to key service pid {pid} failed: {}",
            std::io::Error::last_os_error()
        );
        // Let the old process go before looking for the new one, or its
        // name is still in the directory and would be mistaken for a
        // service that read these values.
        let until = Instant::now() + Duration::from_secs(5);
        while running(KEYMINT_PROGRAM) == Some(pid) {
            ensure!(
                Instant::now() < until,
                "key service pid {pid} did not end after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    } else {
        skyward_sys::kmsg(
            "the key service is not running yet; waiting for it to register with these values",
        )?;
    }
    let binder =
        skyward_binder::driver::Binder::open().context("open the key driver after the restart")?;
    let until = Instant::now() + Duration::from_secs(10);
    while skyward_binder::service::find(&binder, super::keymint::SERVICE)?.is_none() {
        ensure!(
            Instant::now() < until,
            "the key service did not register after it was asked to read the version again"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    skyward_sys::kmsg("the key service registered again with the installed system's version")?;
    Ok(())
}

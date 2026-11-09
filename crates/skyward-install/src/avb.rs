//! Turning off Android Verified Boot 2.0 the way TWRP R7 for Xiaomi's
//! SM8750 phones does it since its rewrite (YuKongA, 2025-08-11, through
//! libavb_user's avb_user_verity_set): only the top-level vbmeta of each
//! slot is touched, and only its HASHTREE_DISABLED bit is set, so dm-verity
//! is left off while the bootloader still verifies. Setting
//! VERIFICATION_DISABLED as well, or touching the chained vbmeta_system and
//! vbmeta_vendor, is what older recoveries did and what Xiaomi's newer
//! firmware no longer takes: libavb refuses a chained vbmeta image whose
//! flags are not zero.

use anyhow::{ensure, Context, Result};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAGIC: &[u8] = b"AVB0";
/// Where the header's big-endian flags word sits.
const FLAGS_AT: u64 = 120;
const HASHTREE_DISABLED: u32 = 0x1;
const VERIFICATION_DISABLED: u32 = 0x2;
/// The partition whose flags are set.
pub const TOP: &str = "vbmeta";
/// Chained vbmeta partitions, whose flags must stay zero; an earlier
/// Skyward (v6) set them, and they are put back.
pub const CHAINED: [&str; 2] = ["vbmeta_system", "vbmeta_vendor"];

/// What became of one partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Its flags were changed.
    Set,
    /// They were as wanted already.
    Already,
}

/// Rewrite the flags word of `device`, a vbmeta partition, with `change`.
fn rewrite(device: &Path, change: impl Fn(u32) -> u32) -> Result<Done> {
    let mut f = OpenOptions::new().read(true).write(true).open(device).with_context(|| format!("open {}", device.display()))?;
    let mut head = [0u8; 128];
    f.read_exact(&mut head).with_context(|| format!("read {}", device.display()))?;
    ensure!(head.starts_with(MAGIC), "{} holds no vbmeta header", device.display());
    let at = FLAGS_AT as usize;
    let flags = u32::from_be_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    let wanted = change(flags);
    if wanted == flags {
        return Ok(Done::Already);
    }
    let new = wanted.to_be_bytes();
    f.seek(SeekFrom::Start(FLAGS_AT)).with_context(|| format!("seek in {}", device.display()))?;
    f.write_all(&new).with_context(|| format!("write {}", device.display()))?;
    f.sync_all().with_context(|| format!("flush {}", device.display()))?;
    crate::image::drop_cache(&f).with_context(|| format!("drop the cached pages of {}", device.display()))?;
    f.seek(SeekFrom::Start(FLAGS_AT)).with_context(|| format!("seek in {}", device.display()))?;
    let mut back = [0u8; 4];
    f.read_exact(&mut back).with_context(|| format!("read back {}", device.display()))?;
    ensure!(back == new, "{} reads back different flags", device.display());
    Ok(Done::Set)
}

/// Turn dm-verity off in `device`, a top-level vbmeta partition, keeping
/// verification on, as TWRP does: HASHTREE_DISABLED set,
/// VERIFICATION_DISABLED cleared (an earlier Skyward set it).
pub fn disable_one(device: &Path) -> Result<Done> {
    rewrite(device, |f| (f | HASHTREE_DISABLED) & !VERIFICATION_DISABLED)
}

/// Put the flags of a chained vbmeta partition back to zero.
pub fn clear_chained(device: &Path) -> Result<Done> {
    rewrite(device, |_| 0)
}

/// Disable dm-verity in the top-level vbmeta of both slots among the links
/// in `dir`, and put back to zero the flags of any chained vbmeta partition
/// an earlier Skyward set: each partition's name with its slot, and what
/// became of it.
pub fn disable(dir: &Path) -> Vec<(String, Result<Done>)> {
    let mut out = Vec::new();
    for suffix in ["_a", "_b"] {
        let full = format!("{TOP}{suffix}");
        let path = dir.join(&full);
        if path.exists() {
            out.push((full, disable_one(&path)));
        }
    }
    for name in CHAINED {
        for suffix in ["_a", "_b"] {
            let full = format!("{name}{suffix}");
            let path = dir.join(&full);
            if !path.exists() {
                continue;
            }
            match clear_chained(&path) {
                Ok(Done::Already) => {}
                r => out.push((full, r)),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vbmeta(flags: u8) -> Vec<u8> {
        let mut img = vec![0u8; 4096];
        img[..4].copy_from_slice(MAGIC);
        img[123] = flags;
        img
    }

    #[test]
    fn only_verity_is_turned_off_and_chained_flags_go_back_to_zero() {
        let dir = std::env::temp_dir().join(format!("avb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vbmeta_a"), vbmeta(0)).unwrap();
        std::fs::write(dir.join("vbmeta_b"), vbmeta(3)).unwrap();
        std::fs::write(dir.join("vbmeta_system_a"), vbmeta(0)).unwrap();
        std::fs::write(dir.join("vbmeta_system_b"), vbmeta(3)).unwrap();
        let all = disable(&dir);
        assert_eq!(std::fs::read(dir.join("vbmeta_a")).unwrap()[123], 1);
        assert_eq!(std::fs::read(dir.join("vbmeta_b")).unwrap()[123], 1);
        assert_eq!(std::fs::read(dir.join("vbmeta_system_a")).unwrap()[123], 0);
        assert_eq!(std::fs::read(dir.join("vbmeta_system_b")).unwrap()[123], 0);
        let names: Vec<_> = all.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["vbmeta_a", "vbmeta_b", "vbmeta_system_b"]);
        assert!(all.iter().all(|(_, r)| r.as_ref().unwrap() == &Done::Set));
        assert_eq!(disable_one(&dir.join("vbmeta_a")).unwrap(), Done::Already);
        std::fs::write(dir.join("vbmeta_a"), vec![0u8; 256]).unwrap();
        assert!(disable_one(&dir.join("vbmeta_a")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

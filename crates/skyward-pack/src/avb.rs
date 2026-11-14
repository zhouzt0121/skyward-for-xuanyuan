//! The footer a recovery image ends in for the bootloader to verify it by:
//! an unsigned vbmeta image holding the image's digest, laid out over the
//! whole partition as avbtool's `add_hash_footer --algorithm NONE` lays it.
//! An unlocked bootloader boots such an image whatever its digest; it gives
//! up on the whole slot when the footer at the partition's end points at
//! anything but a vbmeta image, as a stock footer left behind an image
//! written over the start of the partition does.

use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

/// The unit avbtool lays an image and its vbmeta image out in.
const BLOCK: usize = 4096;
const FOOTER_LEN: usize = 64;
const HEADER_LEN: usize = 256;
const TAG_PROPERTY: u64 = 0;
const TAG_HASH: u64 = 2;
const RELEASE: &[u8] = b"skyward-pack";

/// `image` grown to fill a `partition_size`-byte partition named
/// `partition`: the image, its vbmeta image from the next block on, and the
/// footer locating that in the partition's last bytes, zeros between.
///
/// `properties` are property descriptors laid after the hash descriptor as
/// they are, normally those of the stock image's own footer: the bootloader
/// reads `com.android.build.<partition>.os_version` and `.security_patch`
/// from them and hands them to the secure world as the boot image's version
/// and patch level. Without them the secure world sees a boot patch level
/// older than the one the system's keys were made under, asks for each key
/// to be upgraded and then refuses the upgrade as a downgrade, so the data
/// partition cannot be opened.
pub fn footed(image: &[u8], partition: &str, partition_size: usize, salt: &[u8], properties: &[u8]) -> Result<Vec<u8>> {
    let digest = Sha256::new().chain_update(salt).chain_update(image).finalize();
    let mut descriptors = hash_descriptor(image.len() as u64, partition, salt, &digest);
    descriptors.extend_from_slice(properties);
    let vbmeta = vbmeta(&descriptors);
    let offset = image.len().next_multiple_of(BLOCK);
    let end = offset + vbmeta.len().next_multiple_of(BLOCK);
    ensure!(
        end + BLOCK <= partition_size,
        "a {}-byte image and its vbmeta image do not fit a {partition_size}-byte {partition} partition beside its footer",
        image.len()
    );
    let mut out = Vec::with_capacity(partition_size);
    out.extend_from_slice(image);
    out.resize(offset, 0);
    out.extend_from_slice(&vbmeta);
    out.resize(partition_size - FOOTER_LEN, 0);
    out.extend_from_slice(b"AVBf");
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    for n in [image.len(), offset, vbmeta.len()] {
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.resize(partition_size, 0);
    Ok(out)
}

/// The property descriptors, as they are, of the vbmeta image the footer at
/// the end of `partition` (a whole partition's bytes) points at; none when it
/// has no footer or the footer points at no vbmeta image.
pub fn properties(partition: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    let be = |b: &[u8], at: usize| -> Option<u64> { Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?)) };
    let parse = || -> Option<Vec<(String, String, Vec<u8>)>> {
        let footer = partition.get(partition.len().checked_sub(FOOTER_LEN)?..)?;
        if &footer[..4] != b"AVBf" {
            return None;
        }
        let offset = be(footer, 20)? as usize;
        let size = be(footer, 28)? as usize;
        let v = partition.get(offset..offset.checked_add(size)?)?;
        if &v[..4] != b"AVB0" {
            return None;
        }
        let aux = HEADER_LEN + be(v, 12)? as usize;
        let start = aux + be(v, 96)? as usize;
        let end = start + be(v, 104)? as usize;
        let d = v.get(start..end)?;
        let mut out = Vec::new();
        let mut at = 0;
        while at + 16 <= d.len() {
            let tag = be(d, at)?;
            let len = 16 + be(d, at + 8)? as usize;
            let one = d.get(at..at + len)?;
            if tag == TAG_PROPERTY && one.len() >= 32 {
                let k = be(one, 16)? as usize;
                let n = be(one, 24)? as usize;
                let key = String::from_utf8_lossy(one.get(32..32 + k)?).into_owned();
                let value = String::from_utf8_lossy(one.get(33 + k..33 + k + n)?).into_owned();
                out.push((key, value, one.to_vec()));
            }
            at += len;
        }
        Some(out)
    };
    parse().unwrap_or_default()
}

/// A property descriptor binding `key` to `value`, as avbtool lays one.
#[cfg(test)]
pub fn property(key: &str, value: &str) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&TAG_PROPERTY.to_be_bytes());
    d.extend_from_slice(&0u64.to_be_bytes());
    d.extend_from_slice(&(key.len() as u64).to_be_bytes());
    d.extend_from_slice(&(value.len() as u64).to_be_bytes());
    d.extend_from_slice(key.as_bytes());
    d.push(0);
    d.extend_from_slice(value.as_bytes());
    d.push(0);
    d.resize(d.len().next_multiple_of(8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

/// A descriptor saying the first `image_size` bytes of `partition`, salted
/// with `salt`, hash to `digest` under SHA-256.
fn hash_descriptor(image_size: u64, partition: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut algorithm = [0u8; 32];
    algorithm[..6].copy_from_slice(b"sha256");
    let mut d = Vec::new();
    d.extend_from_slice(&TAG_HASH.to_be_bytes());
    // How many bytes follow these first sixteen, once they are known.
    d.extend_from_slice(&0u64.to_be_bytes());
    d.extend_from_slice(&image_size.to_be_bytes());
    d.extend_from_slice(&algorithm);
    // The lengths of the name, salt and digest, then the flags.
    for n in [partition.len(), salt.len(), digest.len(), 0] {
        d.extend_from_slice(&(n as u32).to_be_bytes());
    }
    d.extend_from_slice(&[0; 60]);
    d.extend_from_slice(partition.as_bytes());
    d.extend_from_slice(salt);
    d.extend_from_slice(digest);
    d.resize(d.len().next_multiple_of(8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

/// An unsigned vbmeta image holding `descriptors`: its header, an empty
/// authentication block and the descriptors as its auxiliary block.
fn vbmeta(descriptors: &[u8]) -> Vec<u8> {
    let aux = descriptors.len().next_multiple_of(64);
    let mut v = Vec::with_capacity(HEADER_LEN + aux);
    v.extend_from_slice(b"AVB0");
    // The libavb version it needs, 1.0.
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u64.to_be_bytes());
    v.extend_from_slice(&(aux as u64).to_be_bytes());
    // No signing algorithm.
    v.extend_from_slice(&0u32.to_be_bytes());
    // The offsets and sizes of the hash, the signature, the public key, its
    // metadata and the descriptors, then the rollback index.
    let n = descriptors.len();
    for field in [0, 0, 0, 0, n, 0, n, 0, 0, n, 0] {
        v.extend_from_slice(&(field as u64).to_be_bytes());
    }
    // The flags and the rollback index location.
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(RELEASE);
    v.resize(HEADER_LEN, 0);
    v.extend_from_slice(descriptors);
    v.resize(HEADER_LEN + aux, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [0x5a; 32];

    /// What avbtool 1.4.0 makes of `len` bytes of `S`, given by
    /// `add_hash_footer --partition_size 81920 --partition_name recovery
    /// --algorithm NONE --salt 5a…5a --internal_release_string skyward-pack`.
    fn avbtool(len: usize) -> &'static [u8] {
        match len {
            4096 => include_bytes!("../tests/avb-footer-4096.bin"),
            1000 => include_bytes!("../tests/avb-footer-1000.bin"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn the_footer_is_avbtools_byte_for_byte() {
        for len in [4096, 1000] {
            let got = footed(&vec![b'S'; len], "recovery", 81920, &SALT, &[]).unwrap();
            assert!(got == avbtool(len), "a {len}-byte image");
        }
    }

    #[test]
    fn the_stock_footers_properties_are_carried_over() {
        let props = [property("com.android.build.recovery.os_version", "15"), property("com.android.build.recovery.security_patch", "2026-10-01")].concat();
        let got = footed(&vec![b'S'; 4096], "recovery", 81920, &SALT, &props).unwrap();
        let read = properties(&got);
        assert_eq!(read.len(), 2);
        assert_eq!((read[0].0.as_str(), read[0].1.as_str()), ("com.android.build.recovery.os_version", "15"));
        assert_eq!((read[1].0.as_str(), read[1].1.as_str()), ("com.android.build.recovery.security_patch", "2026-10-01"));
        assert!(properties(&footed(&vec![b'S'; 4096], "recovery", 81920, &SALT, &[]).unwrap()).is_empty());
    }

    #[test]
    fn an_image_that_leaves_no_room_for_its_vbmeta_and_footer_is_refused() {
        let image = vec![b'S'; 8192];
        assert!(footed(&image, "recovery", 16384, &SALT, &[]).is_ok(), "a block each for the vbmeta image and the footer");
        assert!(footed(&image, "recovery", 12288, &SALT, &[]).is_err());
    }
}

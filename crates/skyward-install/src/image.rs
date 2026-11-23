//! Partition images that come over sideload: what an image is from its
//! header and ramdisk, which partitions it can go to, and writing it to
//! them the way fastboot does.

use abootimg_oxide::binrw::BinRead;
use abootimg_oxide::binrw::io::Cursor;
use abootimg_oxide::{Header, VendorHeader};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use skyward_vab::Slot;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const BOOT_MAGIC: &[u8] = b"ANDROID!";
const VENDOR_BOOT_MAGIC: &[u8] = b"VNDRBOOT";
/// A dtbo image starts with this, big-endian.
const DTBO_MAGIC: &[u8] = &[0xd7, 0xb7, 0xab, 0x1e];
const VBMETA_MAGIC: &[u8] = b"AVB0";
/// An Android sparse image, as fastboot and ROM packages carry super.
const SPARSE_MAGIC: &[u8] = &[0x3a, 0xff, 0x26, 0xed];
/// The geometry of logical partitions, 4096 bytes into super.
const LP_GEOMETRY_MAGIC: &[u8] = &[0x67, 0x44, 0x6c, 0x61];
const LP_GEOMETRY_AT: u64 = 4096;
const CHUNK_RAW: u16 = 0xcac1;
const CHUNK_FILL: u16 = 0xcac2;
const CHUNK_DONT_CARE: u16 = 0xcac3;
const CHUNK_CRC32: u16 = 0xcac4;

/// How a ramdisk is packed, by its first bytes: LZ4 in the legacy framing
/// Android uses or the standard one, gzip, or a bare newc archive.
const LZ4_LEGACY: &[u8] = &[0x02, 0x21, 0x4c, 0x18];
const LZ4_FRAME: &[u8] = &[0x04, 0x22, 0x4d, 0x18];
const GZIP: &[u8] = &[0x1f, 0x8b];
const NEWC: &[u8] = b"070701";

/// Where a recovery's ramdisk keeps its program, now and in older layouts.
const RECOVERY_PROGRAMS: [&str; 2] = ["system/bin/recovery", "sbin/recovery"];

/// A signed image ends with a footer that locates its signature, and the
/// bootloader looks for it in the last bytes of the partition.
const FOOTER_MAGIC: &[u8] = b"AVBf";
const FOOTER_LEN: u64 = 64;

const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// A boot image; what it carries decides where it can go.
    Boot {
        kernel: bool,
        ramdisk: Ramdisk,
    },
    VendorBoot,
    Dtbo,
    Vbmeta,
    /// The whole super partition, every slot's logical partitions in it,
    /// raw or as a sparse image.
    Super {
        sparse: bool,
    },
    /// A filesystem image (erofs, ext4, f2fs) for one of a slot's logical
    /// partitions in super, raw or sparse.
    Logical {
        sparse: bool,
    },
}

/// The ramdisk a boot image carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ramdisk {
    None,
    /// The one that starts Android.
    Generic,
    /// A recovery's, which holds the recovery program.
    Recovery,
}

impl ImageKind {
    /// The partitions an image of this kind can go to, the likeliest first.
    /// A recovery that brings its own kernel can also be the boot image of
    /// a phone whose recovery lives in boot; without one it needs boot's.
    pub fn partitions(self) -> &'static [&'static str] {
        match self {
            ImageKind::Boot {
                kernel: true,
                ramdisk: Ramdisk::Recovery,
            } => &["recovery", "boot"],
            ImageKind::Boot {
                kernel: false,
                ramdisk: Ramdisk::Recovery,
            } => &["recovery"],
            ImageKind::Boot { kernel: true, .. } => &["boot"],
            ImageKind::Boot { kernel: false, .. } => &["init_boot"],
            ImageKind::VendorBoot => &["vendor_boot"],
            ImageKind::Dtbo => &["dtbo"],
            ImageKind::Vbmeta => &["vbmeta", "vbmeta_system", "vbmeta_vendor"],
            ImageKind::Super { .. } => &["super"],
            // Which ones there are is read from super as it is flashed.
            ImageKind::Logical { .. } => &[],
        }
    }

    /// Whether the image goes to one partition that has no slots.
    pub fn unslotted(self) -> bool {
        matches!(self, ImageKind::Super { .. })
    }
}

/// The image `file` holds, from `head`, its first bytes, and for a boot
/// image its ramdisk; `None` when it is no image this recovery writes.
pub fn detect<R: Read + Seek>(file: &mut R, head: &[u8]) -> Result<Option<ImageKind>> {
    if head.starts_with(BOOT_MAGIC) {
        let header = Header::parse(&mut Cursor::new(head)).context("read the boot image header")?;
        let kernel = header.kernel_size() > 0;
        let ramdisk = match header.ramdisk_size() {
            0 => Ramdisk::None,
            size => {
                file.seek(SeekFrom::Start(header.ramdisk_position() as u64))
                    .context("seek to the ramdisk")?;
                ramdisk(file.take(u64::from(size))).context("read the ramdisk")?
            }
        };
        ensure!(
            kernel || ramdisk != Ramdisk::None,
            "the boot image holds neither a kernel nor a ramdisk"
        );
        return Ok(Some(ImageKind::Boot { kernel, ramdisk }));
    }
    if head.starts_with(VENDOR_BOOT_MAGIC) {
        VendorHeader::read(&mut Cursor::new(head)).context("read the vendor boot image header")?;
        return Ok(Some(ImageKind::VendorBoot));
    }
    if head.starts_with(DTBO_MAGIC) {
        return Ok(Some(ImageKind::Dtbo));
    }
    if head.starts_with(VBMETA_MAGIC) {
        return Ok(Some(ImageKind::Vbmeta));
    }
    if head.starts_with(SPARSE_MAGIC) {
        if sparse_bytes_at(file, LP_GEOMETRY_AT)?.is_some_and(|b| b == LP_GEOMETRY_MAGIC) {
            return Ok(Some(ImageKind::Super { sparse: true }));
        }
        let fs = [(1024, EROFS_MAGIC), (1024, F2FS_MAGIC), (1080, EXT4_MAGIC)];
        for (at, magic) in fs {
            if let Some(b) = sparse_bytes_at(file, at)? {
                if b[..magic.len()] == *magic {
                    return Ok(Some(ImageKind::Logical { sparse: true }));
                }
            }
        }
        return Ok(None);
    }
    file.seek(SeekFrom::Start(LP_GEOMETRY_AT))
        .context("seek to the logical partition geometry")?;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_ok() && magic == LP_GEOMETRY_MAGIC {
        return Ok(Some(ImageKind::Super { sparse: false }));
    }
    let mut at1024 = [0u8; 64];
    file.seek(SeekFrom::Start(1024))
        .context("seek to the superblock")?;
    if file.read_exact(&mut at1024).is_ok()
        && (at1024.starts_with(EROFS_MAGIC)
            || at1024.starts_with(F2FS_MAGIC)
            || at1024[56..58] == *EXT4_MAGIC)
    {
        return Ok(Some(ImageKind::Logical { sparse: false }));
    }
    Ok(None)
}

const EROFS_MAGIC: &[u8] = &[0xe2, 0xe1, 0xf5, 0xe0];
const F2FS_MAGIC: &[u8] = &[0x10, 0x20, 0xf5, 0xf2];
const EXT4_MAGIC: &[u8] = &[0x53, 0xef];

/// A sparse image's header.
#[derive(Debug, Clone, Copy)]
struct SparseHeader {
    file_hdr: u16,
    chunk_hdr: u16,
    block: u32,
    blocks: u32,
    chunks: u32,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn sparse_header<R: Read + Seek>(file: &mut R) -> Result<SparseHeader> {
    file.seek(SeekFrom::Start(0))
        .context("rewind the sparse image")?;
    let mut h = [0u8; 28];
    file.read_exact(&mut h).context("read the sparse header")?;
    ensure!(h[..4] == *SPARSE_MAGIC, "not a sparse image");
    ensure!(
        le16(&h, 4) == 1,
        "sparse image of major version {}",
        le16(&h, 4)
    );
    let header = SparseHeader {
        file_hdr: le16(&h, 8),
        chunk_hdr: le16(&h, 10),
        block: le32(&h, 12),
        blocks: le32(&h, 16),
        chunks: le32(&h, 20),
    };
    ensure!(
        header.file_hdr >= 28 && header.chunk_hdr >= 12,
        "a sparse header too short"
    );
    ensure!(
        header.block > 0 && header.block % 4 == 0,
        "a sparse block size of {}",
        header.block
    );
    Ok(header)
}

/// One chunk of a sparse image: its type, its length in output bytes, and
/// where its data starts in the file and how long it is there.
struct SparseChunk {
    kind: u16,
    out: u64,
    data_at: u64,
}

fn sparse_chunks<R: Read + Seek>(file: &mut R, h: &SparseHeader) -> Result<Vec<SparseChunk>> {
    let mut at = u64::from(h.file_hdr);
    let mut chunks = Vec::with_capacity(h.chunks as usize);
    let mut c = vec![0u8; h.chunk_hdr as usize];
    let mut blocks = 0u64;
    for _ in 0..h.chunks {
        file.seek(SeekFrom::Start(at))
            .context("seek to a sparse chunk")?;
        file.read_exact(&mut c)
            .context("read a sparse chunk header")?;
        let (kind, size, total) = (le16(&c, 0), u64::from(le32(&c, 4)), u64::from(le32(&c, 8)));
        ensure!(
            total >= u64::from(h.chunk_hdr),
            "a sparse chunk shorter than its header"
        );
        let data_len = total - u64::from(h.chunk_hdr);
        let out = size * u64::from(h.block);
        match kind {
            CHUNK_RAW => ensure!(data_len == out, "a raw chunk of {data_len} bytes for {out}"),
            CHUNK_FILL => ensure!(data_len == 4, "a fill chunk of {data_len} bytes"),
            CHUNK_DONT_CARE => {}
            CHUNK_CRC32 => {}
            other => bail!("a sparse chunk of unknown type {other:#x}"),
        }
        if kind != CHUNK_CRC32 {
            blocks += size;
        }
        chunks.push(SparseChunk {
            kind,
            out: if kind == CHUNK_CRC32 { 0 } else { out },
            data_at: at + u64::from(h.chunk_hdr),
        });
        at += total;
    }
    ensure!(
        blocks == u64::from(h.blocks),
        "sparse chunks cover {blocks} blocks of {}",
        h.blocks
    );
    Ok(chunks)
}

/// The 4 bytes a sparse image expands to at `offset`; none where it leaves
/// them alone.
fn sparse_bytes_at<R: Read + Seek>(file: &mut R, offset: u64) -> Result<Option<[u8; 4]>> {
    let h = match sparse_header(file) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };
    let chunks = match sparse_chunks(file, &h) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let mut pos = 0u64;
    for c in chunks {
        if offset >= pos && offset + 4 <= pos + c.out {
            let mut b = [0u8; 4];
            match c.kind {
                CHUNK_RAW => {
                    file.seek(SeekFrom::Start(c.data_at + (offset - pos)))
                        .context("seek into a raw chunk")?;
                    file.read_exact(&mut b).context("read a raw chunk")?;
                }
                CHUNK_FILL => {
                    file.seek(SeekFrom::Start(c.data_at))
                        .context("seek to a fill value")?;
                    let mut v = [0u8; 4];
                    file.read_exact(&mut v).context("read a fill value")?;
                    for (k, x) in b.iter_mut().enumerate() {
                        *x = v[((offset - pos) as usize + k) % 4];
                    }
                }
                _ => return Ok(None),
            }
            return Ok(Some(b));
        }
        pos += c.out;
    }
    Ok(None)
}

/// The bytes a sparse image expands to.
pub fn sparse_size<R: Read + Seek>(file: &mut R) -> Result<u64> {
    let h = sparse_header(file)?;
    Ok(u64::from(h.blocks) * u64::from(h.block))
}

/// Write a sparse image to `device`, block by block as its chunks say,
/// leaving what it does not care about alone, then read back what it wrote
/// and compare. `progress` hears the bytes written and read back so far.
pub fn flash_sparse<R: Read + Seek>(
    image: &mut R,
    device: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    let h = sparse_header(image)?;
    let chunks = sparse_chunks(image, &h)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .with_context(|| format!("open {}", device.display()))?;
    let size = f
        .seek(SeekFrom::End(0))
        .with_context(|| format!("find the size of {}", device.display()))?;
    let expanded = u64::from(h.blocks) * u64::from(h.block);
    ensure!(
        expanded <= size,
        "the image expands to {expanded} bytes, more than the {size} its partition holds"
    );
    let written: u64 = chunks
        .iter()
        .filter(|c| matches!(c.kind, CHUNK_RAW | CHUNK_FILL))
        .map(|c| c.out)
        .sum();
    let verify = written <= VERIFY_UP_TO;
    let total = if verify { written * 2 } else { written };
    let mut done = 0u64;
    let _ = size;
    let mut buf = vec![0u8; BIG_CHUNK];
    let mut sum = Sha256::new();
    let mut pos = 0u64;
    for c in &chunks {
        match c.kind {
            CHUNK_RAW | CHUNK_FILL => {
                f.seek(SeekFrom::Start(pos))
                    .with_context(|| format!("seek in {}", device.display()))?;
                let mut fill = [0u8; 4];
                if c.kind == CHUNK_FILL {
                    image
                        .seek(SeekFrom::Start(c.data_at))
                        .context("seek to a fill value")?;
                    image.read_exact(&mut fill).context("read a fill value")?;
                    for k in 0..BIG_CHUNK {
                        buf[k] = fill[k % 4];
                    }
                } else {
                    image
                        .seek(SeekFrom::Start(c.data_at))
                        .context("seek to a raw chunk")?;
                }
                let mut left = c.out;
                while left > 0 {
                    let n = left.min(BIG_CHUNK as u64) as usize;
                    if c.kind == CHUNK_RAW {
                        image.read_exact(&mut buf[..n]).context("read the image")?;
                    }
                    if verify {
                        sum.update(&buf[..n]);
                    }
                    f.write_all(&buf[..n])
                        .with_context(|| format!("write {}", device.display()))?;
                    left -= n as u64;
                    done += n as u64;
                    progress(done, total);
                }
            }
            _ => {}
        }
        pos += c.out;
    }
    f.sync_all()
        .with_context(|| format!("flush {}", device.display()))?;
    drop_cache(&f).with_context(|| format!("drop the cached pages of {}", device.display()))?;
    if !verify {
        return Ok(());
    }
    let mut back = Sha256::new();
    let mut pos = 0u64;
    for c in &chunks {
        if matches!(c.kind, CHUNK_RAW | CHUNK_FILL) {
            f.seek(SeekFrom::Start(pos))
                .with_context(|| format!("seek in {}", device.display()))?;
            let mut left = c.out;
            while left > 0 {
                let n = left.min(BIG_CHUNK as u64) as usize;
                f.read_exact(&mut buf[..n])
                    .with_context(|| format!("read back {}", device.display()))?;
                back.update(&buf[..n]);
                left -= n as u64;
                done += n as u64;
                progress(done, total);
            }
        }
        pos += c.out;
    }
    ensure!(
        back.finalize() == sum.finalize(),
        "{} reads back different from what was written",
        device.display()
    );
    Ok(())
}

/// Whether a packed ramdisk is a recovery's, by the names in its archive.
fn ramdisk(packed: impl Read) -> Result<Ramdisk> {
    Ok(
        match holds(packed, |name| RECOVERY_PROGRAMS.contains(&name))? {
            true => Ramdisk::Recovery,
            false => Ramdisk::Generic,
        },
    )
}

/// Whether a packed ramdisk has an entry whose name `wanted` picks.
fn holds(packed: impl Read, wanted: impl Fn(&str) -> bool) -> Result<bool> {
    Ok(find(packed, wanted, |_| Ok(()))?.is_some())
}

/// What `take` makes of the first entry of a packed ramdisk whose name
/// `wanted` picks, read from its start; none when no entry's name is
/// picked.
fn find<T>(
    packed: impl Read,
    wanted: impl Fn(&str) -> bool,
    take: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<Option<T>> {
    let mut packed = BufReader::new(packed);
    let start = packed
        .fill_buf()
        .context("read the ramdisk's first bytes")?;
    let mut rest: Box<dyn Read + '_> =
        if start.starts_with(LZ4_LEGACY) || start.starts_with(LZ4_FRAME) {
            Box::new(lz4_flex::frame::FrameDecoder::new(packed))
        } else if start.starts_with(GZIP) {
            Box::new(flate2::bufread::MultiGzDecoder::new(packed))
        } else if start.starts_with(NEWC) {
            Box::new(packed)
        } else {
            bail!(
                "a ramdisk packed in an unknown way, starting {:02x?}",
                &start[..start.len().min(4)]
            );
        };
    loop {
        let mut entry = cpio::NewcReader::new(rest).context("read a ramdisk entry")?;
        if entry.entry().is_trailer() {
            return Ok(None);
        }
        if wanted(entry.entry().name().trim_start_matches("./")) {
            return take(&mut entry).map(Some);
        }
        rest = entry.finish().context("read past a ramdisk entry")?;
    }
}

/// Whether `file` is a Skyward recovery: a boot image whose ramdisk carries
/// the device configuration Skyward is packed with, packed in one of the
/// ways read here, as Skyward packs it.
pub fn is_skyward<R: Read + Seek>(file: &mut R) -> Result<bool> {
    Ok(device_config(file)?.is_some())
}

/// [`is_skyward`], naming the file in the kernel log when the image cannot be
/// read: an image this build cannot read is not taken for Skyward, and the
/// reason is worth keeping.
pub fn is_skyward_at<R: Read + Seek>(file: &mut R, path: &Path) -> Result<bool> {
    Ok(match is_skyward(file) {
        Ok(skyward) => skyward,
        Err(error) => {
            let _ = skyward_sys::kmsg(&format!(
                "install: {} holds an image this build cannot read, so it is not taken for Skyward: {error:#}",
                path.display()
            ));
            false
        }
    })
}

/// The device configuration a Skyward recovery carries in its ramdisk;
/// none when `file` is no Skyward recovery.
pub fn device_config<R: Read + Seek>(file: &mut R) -> Result<Option<Vec<u8>>> {
    let mut head = Vec::with_capacity(4096);
    file.take(4096)
        .read_to_end(&mut head)
        .context("read the image's first bytes")?;
    if !head.starts_with(BOOT_MAGIC) {
        return Ok(None);
    }
    let header = Header::parse(&mut Cursor::new(&head)).context("read the boot image header")?;
    if header.ramdisk_size() == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(header.ramdisk_position() as u64))
        .context("seek to the ramdisk")?;
    let mut ramdisk = BufReader::new(file.take(u64::from(header.ramdisk_size())));
    let start = ramdisk
        .fill_buf()
        .context("read the ramdisk's first bytes")?;
    if ![LZ4_LEGACY, LZ4_FRAME, GZIP, NEWC]
        .iter()
        .any(|magic| start.starts_with(magic))
    {
        return Ok(None);
    }
    let read = |entry: &mut dyn Read| {
        let mut config = Vec::new();
        entry
            .read_to_end(&mut config)
            .context("read the device configuration")?;
        Ok(config)
    };
    find(
        ramdisk,
        |name| name == skyward_config::ramdisk::CONFIG,
        read,
    )
    .context("read the ramdisk")
}

/// The partition `name` of `slot` among the links in `dir`.
pub fn device(dir: &Path, name: &str, slot: Slot) -> PathBuf {
    dir.join(format!("{name}{}", slot.suffix()))
}

/// The partitions `kind` fits that this phone has in both slots, among the
/// links in `dir`, the likeliest first.
pub fn partitions(kind: ImageKind, dir: &Path) -> Result<Vec<&'static str>> {
    let mut found = Vec::new();
    if kind.unslotted() {
        for name in kind.partitions() {
            let path = dir.join(name);
            if path
                .try_exists()
                .with_context(|| format!("look for {}", path.display()))?
            {
                found.push(*name);
            }
        }
        return Ok(found);
    }
    for name in kind.partitions() {
        let mut has = true;
        for slot in [Slot::A, Slot::B] {
            let path = device(dir, name, slot);
            has &= path
                .try_exists()
                .with_context(|| format!("look for {}", path.display()))?;
        }
        if has {
            found.push(*name);
        }
    }
    Ok(found)
}

/// Images up to this size are read back and compared after writing; a
/// larger one (super, a slot's system) is written once, as TWRP and
/// fastboot write it, since reading back gigabytes doubles the wait.
pub const VERIFY_UP_TO: u64 = 512 << 20;

/// How much a write or a read moves at once, for the big images.
const BIG_CHUNK: usize = 8 << 20;

/// Read `end` bytes of `source` on a thread of its own, handing each
/// chunk to `sink` as it comes, so reading the package and writing the
/// partition overlap.
fn pipelined<R: Read + Send>(
    source: &mut R,
    end: u64,
    chunk: usize,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    use std::sync::mpsc;
    std::thread::scope(|scope| -> Result<()> {
        let (full_tx, full_rx) = mpsc::sync_channel::<Result<Vec<u8>>>(3);
        let (empty_tx, empty_rx) = mpsc::channel::<Vec<u8>>();
        for _ in 0..4 {
            let _ = empty_tx.send(vec![0u8; chunk]);
        }
        scope.spawn(move || {
            let mut at = 0u64;
            while at < end {
                let Ok(mut buf) = empty_rx.recv() else { return };
                let n = (end - at).min(chunk as u64) as usize;
                buf.resize(n, 0);
                let r = source.read_exact(&mut buf).context("read the image");
                let failed = r.is_err();
                if full_tx.send(r.map(|_| buf)).is_err() || failed {
                    return;
                }
                at += n as u64;
            }
        });
        let mut at = 0u64;
        while at < end {
            let buf = full_rx.recv().context("the image reader stopped")??;
            sink(&buf)?;
            at += buf.len() as u64;
            let _ = empty_tx.send(buf);
        }
        Ok(())
    })
}

/// Write `len` bytes of `image` to all of `devices` in one pass, then,
/// for an image no bigger than [`VERIFY_UP_TO`], read each back and
/// compare. A signed image smaller than its partition gets its footer
/// moved to the partition's end, with zeros between, as fastboot does.
/// `progress` hears the bytes written and read back so far, of all.
pub fn flash<R: Read + Seek + Send>(
    image: &mut R,
    len: u64,
    devices: &[PathBuf],
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    ensure!(!devices.is_empty(), "no partition to write");
    let mut outs = Vec::with_capacity(devices.len());
    for path in devices {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let size = f
            .seek(SeekFrom::End(0))
            .with_context(|| format!("find the size of {}", path.display()))?;
        f.seek(SeekFrom::Start(0))
            .with_context(|| format!("rewind {}", path.display()))?;
        outs.push((path, f, size));
    }
    let size = outs[0].2;
    ensure!(
        outs.iter().all(|(_, _, s)| *s == size),
        "the partition differs in size between slots"
    );
    ensure!(
        len <= size,
        "the image is {len} bytes, more than the {size} its partition holds"
    );

    let mut footer = [0u8; FOOTER_LEN as usize];
    let moved = len >= FOOTER_LEN && len < size && {
        image
            .seek(SeekFrom::Start(len - FOOTER_LEN))
            .context("seek to the image's end")?;
        image
            .read_exact(&mut footer)
            .context("read the image's end")?;
        footer.starts_with(FOOTER_MAGIC)
    };
    image.seek(SeekFrom::Start(0)).context("rewind the image")?;
    let (gap, tail): (u64, Vec<u8>) = if moved {
        (size - len - FOOTER_LEN, footer.to_vec())
    } else {
        (0, Vec::new())
    };
    let end = len + gap + tail.len() as u64;
    let verify = end <= VERIFY_UP_TO;
    let total = end * outs.len() as u64 * if verify { 2 } else { 1 };
    let mut source = image
        .take(len)
        .chain(io::repeat(0).take(gap))
        .chain(io::Cursor::new(tail));
    let chunk = if verify { CHUNK } else { BIG_CHUNK };

    let mut written = Sha256::new();
    let mut done = 0;
    pipelined(&mut source, end, chunk, &mut |buf| {
        if verify {
            written.update(buf);
        }
        for (path, f, _) in outs.iter_mut() {
            f.write_all(buf)
                .with_context(|| format!("write {}", path.display()))?;
            done += buf.len() as u64;
            progress(done, total);
        }
        Ok(())
    })?;
    let written = written.finalize();
    for (path, f, _) in &mut outs {
        f.sync_all()
            .with_context(|| format!("flush {}", path.display()))?;
        drop_cache(f).with_context(|| format!("drop the cached pages of {}", path.display()))?;
    }
    if !verify {
        return Ok(());
    }
    let mut buf = vec![0u8; chunk];
    for (path, f, _) in &mut outs {
        f.seek(SeekFrom::Start(0))
            .with_context(|| format!("rewind {}", path.display()))?;
        let mut back = Sha256::new();
        let mut left = end;
        while left > 0 {
            let n = left.min(chunk as u64) as usize;
            f.read_exact(&mut buf[..n])
                .with_context(|| format!("read back {}", path.display()))?;
            back.update(&buf[..n]);
            left -= n as u64;
            done += n as u64;
            progress(done, total);
        }
        ensure!(
            back.finalize() == written,
            "{} reads back different from what was written",
            path.display()
        );
    }
    Ok(())
}

pub(crate) use skyward_block::drop_cache;

/// Images made up for the tests here and in the modules that look into
/// partitions.
#[cfg(test)]
pub(crate) mod samples {
    use super::*;
    use abootimg_oxide::{HeaderV3, OsVersionPatch};

    /// A version 4 boot image with a kernel of `kernel` bytes and `ramdisk`
    /// as its ramdisk, each padded to the page.
    pub fn boot_image(kernel: u32, ramdisk: &[u8]) -> Vec<u8> {
        let header = Header::V3(HeaderV3 {
            kernel_size: kernel,
            ramdisk_size: ramdisk.len() as u32,
            osversionpatch: OsVersionPatch(0),
            cmdline: Box::new([0; 1536]),
            v4_signature_size: Some(0),
        });
        let mut out = Vec::new();
        header.write(&mut out).unwrap();
        out.resize(4096, 0);
        out.resize(4096 + (kernel as usize).div_ceil(4096) * 4096, 0x4b);
        out.extend_from_slice(ramdisk);
        out.resize(out.len().div_ceil(4096) * 4096, 0);
        out
    }

    /// A newc archive of empty files named `names`.
    pub fn archive(names: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for name in names {
            out = cpio::NewcBuilder::new(name)
                .mode(0o100644)
                .write(out, 0)
                .finish()
                .unwrap();
        }
        cpio::newc::trailer(out).unwrap()
    }

    pub use skyward_bootimg::lz4_legacy;

    /// A recovery image, Skyward's or the stock one it is packed on.
    pub fn recovery(skyward: bool) -> Vec<u8> {
        let mut names = vec!["init", "system/bin/recovery", "prop.default"];
        if skyward {
            names.extend(["skyward", "skyward/device.toml", "skyward/MiSansVF.ttf"]);
        }
        boot_image(0, &lz4_legacy(&archive(&names)))
    }

    /// Skyward's recovery for the phone `codename` names, its device
    /// configuration naming it.
    pub fn skyward_for(codename: &str) -> Vec<u8> {
        let config = format!("[device]\ncodename = \"{codename}\"\n");
        let mut out = Vec::new();
        for (name, data) in [
            ("init", &b""[..]),
            ("system/bin/recovery", b""),
            ("skyward/device.toml", config.as_bytes()),
        ] {
            let mut entry = cpio::NewcBuilder::new(name)
                .mode(0o100644)
                .write(out, data.len() as u32);
            entry.write_all(data).unwrap();
            out = entry.finish().unwrap();
        }
        boot_image(0, &lz4_legacy(&cpio::newc::trailer(out).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::samples::{archive, boot_image, lz4_legacy, recovery, skyward_for};
    use super::*;
    use abootimg_oxide::VendorHeaderV4;
    use abootimg_oxide::binrw::BinWrite;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn kind_of(image: &[u8]) -> Result<Option<ImageKind>> {
        detect(&mut Cursor::new(image), &image[..image.len().min(4096)])
    }

    #[test]
    fn boot_images_go_where_what_they_carry_fits() {
        let recovery = archive(&[
            "init",
            "system",
            "system/bin",
            "system/bin/recovery",
            "sbin",
        ]);
        let generic = archive(&["init", "first_stage_ramdisk", "system/bin/snapuserd"]);

        let kind = kind_of(&boot_image(0, &lz4_legacy(&recovery)))
            .unwrap()
            .unwrap();
        assert_eq!(
            kind,
            ImageKind::Boot {
                kernel: false,
                ramdisk: Ramdisk::Recovery
            }
        );
        assert_eq!(kind.partitions(), ["recovery"]);
        let kind = kind_of(&boot_image(0, &gzip(&generic))).unwrap().unwrap();
        assert_eq!(
            kind,
            ImageKind::Boot {
                kernel: false,
                ramdisk: Ramdisk::Generic
            }
        );
        assert_eq!(kind.partitions(), ["init_boot"]);
        let kind = kind_of(&boot_image(5000, &recovery)).unwrap().unwrap();
        assert_eq!(kind.partitions(), ["recovery", "boot"]);
        let kind = kind_of(&boot_image(5000, &lz4_legacy(&generic)))
            .unwrap()
            .unwrap();
        assert_eq!(
            kind,
            ImageKind::Boot {
                kernel: true,
                ramdisk: Ramdisk::Generic
            }
        );
        assert_eq!(kind.partitions(), ["boot"]);
        assert_eq!(
            kind_of(&boot_image(5000, &[])).unwrap(),
            Some(ImageKind::Boot {
                kernel: true,
                ramdisk: Ramdisk::None
            })
        );

        assert!(kind_of(&boot_image(0, &[])).is_err());
        assert!(
            kind_of(&boot_image(0, b"BZh91AY&SY")).is_err(),
            "a ramdisk packed some other way"
        );
        assert!(kind_of(b"ANDROID!").is_err());
    }

    #[test]
    fn skyward_is_told_from_the_stock_recovery_it_is_packed_on() {
        assert!(is_skyward(&mut Cursor::new(recovery(true))).unwrap());
        assert!(!is_skyward(&mut Cursor::new(recovery(false))).unwrap());
        assert!(
            !is_skyward(&mut Cursor::new(boot_image(5000, &[]))).unwrap(),
            "a boot image with no ramdisk"
        );
        assert!(
            !is_skyward(&mut Cursor::new(boot_image(0, b"\xfd7zXZ\0"))).unwrap(),
            "a ramdisk packed as Skyward never packs it"
        );
        assert!(
            !is_skyward(&mut Cursor::new(vec![0u8; 8192])).unwrap(),
            "an erased partition"
        );
    }

    #[test]
    fn skyward_carries_its_device_configuration() {
        let config = device_config(&mut Cursor::new(skyward_for("ishtar")))
            .unwrap()
            .expect("Skyward carries one");
        assert_eq!(config, b"[device]\ncodename = \"ishtar\"\n");
        assert!(is_skyward(&mut Cursor::new(skyward_for("ishtar"))).unwrap());
        assert_eq!(
            device_config(&mut Cursor::new(recovery(false))).unwrap(),
            None
        );
    }

    #[test]
    fn other_images_are_told_by_their_magic() {
        let vendor = VendorHeader {
            page_size: 4096,
            kernel_addr: 0,
            ramdisk_addr: 0,
            vendor_ramdisk_size: 0,
            cmdline: Box::new([0; 2048]),
            tags_addr: 0,
            board_name: [0; 16],
            dtb_size: 0,
            dtb_addr: 0,
            v4: Some(VendorHeaderV4 {
                vendor_ramdisk_table_size: 0,
                vendor_ramdisk_table_entry_num: 0,
                vendor_ramdisk_table_entry_size: 0,
                bootconfig_size: 0,
            }),
        };
        let mut bytes = Cursor::new(Vec::new());
        vendor.write(&mut bytes).unwrap();
        assert_eq!(
            kind_of(bytes.get_ref()).unwrap(),
            Some(ImageKind::VendorBoot)
        );
        assert_eq!(
            kind_of(&[0xd7, 0xb7, 0xab, 0x1e, 0, 0, 0, 0x40]).unwrap(),
            Some(ImageKind::Dtbo)
        );
        assert_eq!(kind_of(b"AVB0\0\0\0\x01").unwrap(), Some(ImageKind::Vbmeta));
        assert_eq!(kind_of(b"\x3a\xff\x26\xed sparse").unwrap(), None);
    }

    #[test]
    fn only_partitions_the_phone_has_in_both_slots_are_offered() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "boot_a",
            "boot_b",
            "recovery_a",
            "recovery_b",
            "init_boot_a",
            "init_boot_b",
            "vbmeta_a",
            "vbmeta_b",
            "vbmeta_system_a",
        ] {
            std::fs::File::create(dir.path().join(name)).unwrap();
        }
        let both = ImageKind::Boot {
            kernel: true,
            ramdisk: Ramdisk::Recovery,
        };
        assert_eq!(partitions(both, dir.path()).unwrap(), ["recovery", "boot"]);
        assert_eq!(
            partitions(ImageKind::Vbmeta, dir.path()).unwrap(),
            ["vbmeta"]
        );
        assert!(partitions(ImageKind::Dtbo, dir.path()).unwrap().is_empty());
    }

    /// A partition of `size` bytes filled with 0xAA, so untouched bytes
    /// show.
    fn partition(dir: &Path, name: &str, size: usize) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, vec![0xaa; size]).unwrap();
        path
    }

    fn flash_all(image: &[u8], devices: &[PathBuf]) -> Result<Vec<(u64, u64)>> {
        let mut seen = Vec::new();
        flash(
            &mut Cursor::new(image),
            image.len() as u64,
            devices,
            &mut |done, total| seen.push((done, total)),
        )?;
        Ok(seen)
    }

    #[test]
    fn an_unsigned_image_leaves_the_rest_of_the_partition_alone() {
        let dir = tempfile::tempdir().unwrap();
        let slots = [
            partition(dir.path(), "dtbo_a", 3 << 20),
            partition(dir.path(), "dtbo_b", 3 << 20),
        ];
        let image: Vec<u8> = (0..(1 << 20) + 300).map(|i| (i % 251) as u8).collect();
        let seen = flash_all(&image, &slots).unwrap();
        for slot in &slots {
            let got = std::fs::read(slot).unwrap();
            assert_eq!(&got[..image.len()], &image[..]);
            assert!(got[image.len()..].iter().all(|&b| b == 0xaa));
        }
        let total = image.len() as u64 * 4;
        assert_eq!(seen.last(), Some(&(total, total)));
        assert!(seen.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn a_signed_image_has_its_footer_moved_to_the_partition_end() {
        let dir = tempfile::tempdir().unwrap();
        let size = 2 << 20;
        let slots = [partition(dir.path(), "boot_a", size)];
        let mut image = vec![0x11u8; 100_000];
        let mut footer = b"AVBf".to_vec();
        footer.resize(FOOTER_LEN as usize, 0x22);
        image.extend_from_slice(&footer);
        flash_all(&image, &slots).unwrap();
        let got = std::fs::read(&slots[0]).unwrap();
        assert_eq!(&got[..image.len()], &image[..]);
        assert!(got[image.len()..size - 64].iter().all(|&b| b == 0));
        assert_eq!(&got[size - 64..], &footer[..]);
    }

    #[test]
    fn an_image_the_size_of_its_partition_is_written_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let slots = [partition(dir.path(), "vbmeta_a", 8192)];
        let mut image = vec![0x33u8; 8192 - 64];
        image.extend_from_slice(b"AVBf");
        image.resize(8192, 0x44);
        flash_all(&image, &slots).unwrap();
        assert_eq!(std::fs::read(&slots[0]).unwrap(), image);
    }

    #[test]
    fn an_image_larger_than_its_partition_is_refused_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let slots = [partition(dir.path(), "dtbo_a", 4096)];
        let err = flash_all(&[1u8; 4097], &slots).unwrap_err();
        assert!(err.to_string().contains("4097"), "{err}");
        assert!(std::fs::read(&slots[0]).unwrap().iter().all(|&b| b == 0xaa));
    }
}

#[cfg(test)]
mod sparse_tests {
    use super::*;
    use std::io::Cursor;

    fn sparse(chunks: &[(u16, u32, Vec<u8>)], block: u32) -> Vec<u8> {
        let blocks: u32 = chunks
            .iter()
            .filter(|c| c.0 != CHUNK_CRC32)
            .map(|c| c.1)
            .sum();
        let mut v = Vec::new();
        v.extend_from_slice(SPARSE_MAGIC);
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&28u16.to_le_bytes());
        v.extend_from_slice(&12u16.to_le_bytes());
        v.extend_from_slice(&block.to_le_bytes());
        v.extend_from_slice(&blocks.to_le_bytes());
        v.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        for (kind, n, data) in chunks {
            v.extend_from_slice(&kind.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(&(12 + data.len() as u32).to_le_bytes());
            v.extend_from_slice(data);
        }
        v
    }

    #[test]
    fn a_sparse_super_is_told_and_written_as_it_expands() {
        let block = 4096u32;
        let mut first = vec![0u8; 8192];
        first[4096..4100].copy_from_slice(LP_GEOMETRY_MAGIC);
        let img = sparse(
            &[
                (CHUNK_RAW, 2, first.clone()),
                (CHUNK_DONT_CARE, 1, vec![]),
                (CHUNK_FILL, 2, vec![0xab, 0xcd, 0xef, 0x01]),
            ],
            block,
        );
        let mut c = Cursor::new(img.clone());
        assert_eq!(
            detect(&mut c, &img[..28]).unwrap(),
            Some(ImageKind::Super { sparse: true })
        );
        assert_eq!(sparse_size(&mut c).unwrap(), 5 * 4096);
        let dir = std::env::temp_dir().join(format!("sparse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dev = dir.join("super");
        std::fs::write(&dev, vec![0x55u8; 6 * 4096]).unwrap();
        flash_sparse(&mut c, &dev, &mut |_, _| {}).unwrap();
        let out = std::fs::read(&dev).unwrap();
        assert_eq!(&out[..8192], &first[..]);
        assert!(
            out[8192..12288].iter().all(|&b| b == 0x55),
            "what it does not care about stays"
        );
        assert_eq!(&out[12288..12292], &[0xab, 0xcd, 0xef, 0x01]);
        assert_eq!(&out[20476..20480], &[0xab, 0xcd, 0xef, 0x01]);
        assert!(out[20480..].iter().all(|&b| b == 0x55));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn filesystem_images_are_logical_partitions() {
        let mut raw = vec![0u8; 8192];
        raw[1024..1028].copy_from_slice(EROFS_MAGIC);
        let mut c = Cursor::new(raw.clone());
        assert_eq!(
            detect(&mut c, &raw[..4096]).unwrap(),
            Some(ImageKind::Logical { sparse: false })
        );
        let mut ext = vec![0u8; 8192];
        ext[1080..1082].copy_from_slice(EXT4_MAGIC);
        let sp = sparse(&[(CHUNK_RAW, 2, ext)], 4096);
        let mut c = Cursor::new(sp.clone());
        assert_eq!(
            detect(&mut c, &sp[..28]).unwrap(),
            Some(ImageKind::Logical { sparse: true })
        );
        let junk = vec![7u8; 8192];
        let mut c = Cursor::new(junk.clone());
        assert_eq!(detect(&mut c, &junk[..4096]).unwrap(), None);
    }
}

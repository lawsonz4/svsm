use super::*;

use crate::address::PhysAddr;
use crate::block::{api::BlockDriver, virtio_blk::VirtIOBlkDriver};
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::locking::RWLock;
use crate::platform::SVSM_PLATFORM;

use core::ops::DerefMut;

unsafe impl Send for VirtIOBlkDriver {}
unsafe impl Sync for VirtIOBlkDriver {}

static BLOCK_DEVICE: RWLock<Option<VirtIOBlkDriver>> = RWLock::new(None);

pub fn initialize_blk() {
    let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());

    let dev = cfg
        .get_virtio_mmio_addresses()
        .unwrap_or_default()
        .iter()
        .find_map(|a| VirtIOBlkDriver::new(PhysAddr::from(*a)).ok())
        .expect("No virtio-blk device found");

    *BLOCK_DEVICE.lock_write().deref_mut() = Some(dev);
}

// Code from https://github.com/rcore-os/rcore-fs/blob/master/rcore-fs/src/dev/mod.rs
// TODO: add proper copyright
pub struct BlockIter {
    pub begin: usize,
    pub end: usize,
    pub block_size_log2: u8,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BlockRange {
    pub block: usize,
    pub begin: usize,
    pub end: usize,
    pub block_size_log2: u8,
}

impl BlockRange {
    //pub fn is_empty(&self) -> bool {
    //    self.end == self.begin
    //}
    pub fn len(&self) -> usize {
        self.end - self.begin
    }
    pub fn is_full(&self) -> bool {
        self.len() == (1usize << self.block_size_log2)
    }
    pub fn origin_begin(&self) -> usize {
        (self.block << self.block_size_log2) + self.begin
    }
    pub fn origin_end(&self) -> usize {
        (self.block << self.block_size_log2) + self.end
    }
}

impl Iterator for BlockIter {
    type Item = BlockRange;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.begin >= self.end {
            return None;
        }
        let block_size_log2 = self.block_size_log2;
        let block_size = 1usize << self.block_size_log2;
        let block = self.begin / block_size;
        let begin = self.begin % block_size;
        let end = if block == self.end / block_size {
            self.end % block_size
        } else {
            block_size
        };
        self.begin += end - begin;
        Some(BlockRange {
            block,
            begin,
            end,
            block_size_log2,
        })
    }
}

macro_rules! try0 {
    ($len:expr, $res:expr) => {
        if $res.is_err() {
            return Ok($len);
        }
    };
}

#[derive(Debug, Default)]
struct RawBlockFile {
    sector: usize,
    size: usize,
}

impl RawBlockFile {
    pub fn new(sector: usize, size: usize) -> Self {
        RawBlockFile { sector, size }
    }

    fn read_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &mut [u8],
    ) -> Result<(), SvsmError> {
        device.read_blocks(self.sector + block_id, buf)
    }

    fn write_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &[u8],
    ) -> Result<(), SvsmError> {
        device.write_blocks(self.sector + block_id, buf)
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::from(FsError::Inval))?;

        let iter = BlockIter {
            begin: offset,
            end: offset + buf.len(),
            block_size_log2: device.block_size_log2(),
        };

        // For each block
        for range in iter {
            let len = range.origin_begin() - offset;
            let buf = &mut buf[range.origin_begin() - offset..range.origin_end() - offset];
            if range.is_full() {
                // Read to target buf directly
                try0!(len, self.read_blocks(device, range.block, buf));
            } else {
                let mut block_buf = [0u8; 1 << 10];
                assert!(device.block_size_log2() <= 10);
                // Read to local buf first
                try0!(len, self.read_blocks(device, range.block, &mut block_buf));
                // Copy to target buf then
                buf.copy_from_slice(&block_buf[range.begin..range.end]);
            }
        }
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::from(FsError::Inval))?;

        let iter = BlockIter {
            begin: offset,
            end: offset + buf.len(),
            block_size_log2: device.block_size_log2(),
        };

        // For each block
        for range in iter {
            let len = range.origin_begin() - offset;
            let buf = &buf[range.origin_begin() - offset..range.origin_end() - offset];
            if range.is_full() {
                // Write to target buf directly
                try0!(len, self.write_blocks(device, range.block, buf));
            } else {
                #[allow(clippy::uninit_assumed_init)]
                let mut block_buf = [0u8; 1 << 10];
                assert!(device.block_size_log2() <= 10);
                // Read to local buf first
                try0!(len, self.read_blocks(device, range.block, &mut block_buf));
                // Write to local buf
                block_buf[range.begin..range.end].copy_from_slice(buf);
                // Write back to target buf
                try0!(len, self.write_blocks(device, range.block, &block_buf));
            }
        }
        Ok(buf.len())
    }

    fn truncate(&self, size: usize) -> Result<usize, SvsmError> {
        if size > self.size {
            return Err(SvsmError::from(FsError::Inval));
        }

        Ok(self.size)
    }

    fn size(&self) -> usize {
        self.size
    }
}

#[derive(Debug)]
pub struct BlockFile {
    rawfile: RWLock<RawBlockFile>,
}

impl BlockFile {
    /// Used to get a new instance of [`BlockFile`].
    #[allow(dead_code)]
    pub fn new(sector: usize, size: usize) -> Self {
        BlockFile {
            rawfile: RWLock::new(RawBlockFile::new(sector, size)),
        }
    }
}

impl File for BlockFile {
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_read().read(buf, offset)
    }

    fn write(&self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_write().write(buf, offset)
    }

    fn truncate(&self, size: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_write().truncate(size)
    }

    fn size(&self) -> usize {
        self.rawfile.lock_read().size()
    }
}

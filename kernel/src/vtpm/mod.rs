// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported

/// TPM 2.0 Reference Implementation
pub mod tcgtpm;

extern crate alloc;

use alloc::vec::Vec;

use crate::vtpm::tcgtpm::TcgTpm as Vtpm;
use crate::vtpm::tcgtpm::tss;

use crate::{locking::LockGuard, protocols::vtpm::TpmPlatformCommand};
use crate::{locking::SpinLock, protocols::errors::SvsmReqError};

/// Basic services required to perform the VTPM Protocol
pub trait VtpmProtocolInterface {
    /// Get the list of Platform Commands supported by the TPM implementation.
    fn get_supported_commands(&self) -> &[TpmPlatformCommand];
}

/// This implements one handler for each [`TpmPlatformCommand`] supported by the
/// VTPM Protocol. These handlers are based on the TPM Simulator interface
/// provided by the TPM 2.0 Reference Implementation, but with a few changes
/// to make it more Rust idiomatic.
///
/// `tpm-20-ref/TPMCmd/Simulator/include/prototypes/Simulator_fp.h`
pub trait TcgTpmSimulatorInterface: VtpmProtocolInterface {
    /// Send a command for the TPM to run in a given locality
    ///
    /// # Arguments
    ///
    /// * `command`: Buffer with the command to be sent to the TPM.
    /// * `locality`: TPM locality the TPM command will be executed
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the response received from the TPM on success,
    /// or an error.
    fn send_tpm_command(&self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError>;

    /// Power-on the TPM, which also triggers a reset
    ///
    /// # Arguments
    ///
    /// *`only_reset``: If enabled, it will only reset the vTPM;
    ///                 however, the vtPM has to be powered on previously.
    ///                 Otherwise, it will fail.
    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError>;

    /// In a system where the NV memory used by the TPM is not within the TPM,
    /// the NV may not always be available. This function indicates that NV
    /// is available.
    fn signal_nvon(&self) -> Result<(), SvsmReqError>;
}

#[derive(Debug)]
pub enum SvsmVTpmError {
    ReqError(SvsmReqError),
    CommandError(u32),
}

impl From<SvsmReqError> for SvsmVTpmError {
    fn from(err: SvsmReqError) -> Self {
        SvsmVTpmError::ReqError(err)
    }
}

impl From<SvsmVTpmError> for SvsmReqError {
    fn from(err: SvsmVTpmError) -> Self {
        match err {
            SvsmVTpmError::ReqError(e) => e,
            SvsmVTpmError::CommandError(_) => SvsmReqError::invalid_request(),
        }
    }
}

/// Basic TPM driver services
pub trait VtpmInterface: TcgTpmSimulatorInterface {
    /// Check if the TPM is powered on.
    fn is_powered_on(&self) -> bool;

    /// Prepare the TPM to be used for the first time. At this stage,
    /// the TPM is manufactured.
    fn init(&mut self, manufacture: bool) -> Result<(), SvsmReqError>;

    /// Returns the cached EK public key if it exists, otherwise it returns an error indicating
    /// that the EK public key does not exist.
    /// Needs mutability to cache the key.
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError>;
}

static VTPM: SpinLock<Vtpm> = SpinLock::new(Vtpm::new());

/// Initialize the TPM by calling the init() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_init(manufacture: bool) -> Result<(), SvsmReqError> {
    let counter_index:Vec<u8> = [0x01, 0xc0, 0x00, 0x01].to_vec();
    let extend_index:Vec<u8> = [0x01, 0xc0, 0x00, 0x02].to_vec();

    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(());
    }
    vtpm.init(manufacture)?;
    // 手动解引用
    let vvtpm: &mut Vtpm = &mut *vtpm;
    // 开机
    let _ = tss::startup(vvtpm);
    // pre getcap
    let  property = [0x01, 0x00, 0x00, 0x00].to_vec();
    let mut is_defined_extend: Option<bool> = Some(false);
    let mut is_defined_counter: Option<bool> = Some(false);
    
    let mut cap_stream = tss::getcap(vvtpm, &property)?;
    parse_getcap(&mut cap_stream, &mut is_defined_extend, &extend_index, &mut is_defined_counter, &counter_index);
    log::info!("is_define status is: counter:{},extend:{}", is_defined_counter.unwrap(), is_defined_extend.unwrap());

    // nvdefine(counter)
    if is_defined_counter == Some(false){
        let _ = tss::nvdefine(vvtpm, &counter_index, &"counter");
    }
    // nvdefine(extend)
    if is_defined_extend == Some(false){
        let _ = tss::nvdefine(vvtpm, &extend_index, &"extend");
    }

    // post getcap
    // property = [0x01, 0x00, 0x00, 0x00].to_vec();
    // cap_stream = tss::getcap(vvtpm, &property)?;
    // parse_getcap(&mut cap_stream, &mut None, &extend_index, &mut None, &counter_index);

    // nv_extend & nv_increment
    _ = tss::nvextend(vvtpm, &extend_index)?;
    _ = tss::nvincrement(vvtpm, &counter_index)?;
    Ok(())
}

pub fn vtpm_get_locked<'a>() -> LockGuard<'a, Vtpm> {
    VTPM.lock()
}

/// Get the TPM manifest i.e the EK public key by calling the get_ekpub() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_get_manifest() -> Result<Vec<u8>, SvsmReqError> {
    let mut vtpm = VTPM.lock();
    vtpm.get_ekpub()
}

fn parse_getcap(cap_stream : &mut Vec<u8>, is_defined_extend :&mut Option<bool>, extend_index: &Vec<u8>, is_defined_counter :&mut Option<bool>, counter_index: &Vec<u8>){
    const BOUND:usize = 19;

    if cap_stream.len() < BOUND{
        log::info!("[getcap] insufficient getcap resp length, error!");
        return
    }else if cap_stream.len() == BOUND{
        log::info!("[getcap] no payload!");
        return
    }

    let index_count = cap_stream[15..BOUND].to_vec();
    let num = u32::from_be_bytes(index_count.try_into().unwrap());
    let rest = cap_stream.split_off(BOUND);
    log::info!("[getcap]nv_index_num is {}, data area is {:02x?}" , num, rest);
    for chunk in rest.chunks_exact(4) {
        let old_index: Vec<u8> = chunk.try_into().unwrap();
        if old_index == *extend_index {
            log::info!("[getcap]extend_index has been existed: 0x{:02x?}, break!", old_index);
            if is_defined_extend.is_some() {
               *is_defined_extend = Some(true);
            }
            continue;
        }else if old_index == *counter_index {
            log::info!("[getcap]counter_index has been existed: 0x{:02x?}, break!", old_index);
            if is_defined_counter.is_some() {
               *is_defined_counter = Some(true);
            }
            continue;    
        }
    }
}

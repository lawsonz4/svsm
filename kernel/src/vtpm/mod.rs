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

use crate::verbose_log;
use crate::detect_log;
use alloc::vec::Vec;
use alloc::string::String;

use crate::vtpm::tcgtpm::TcgTpm as Vtpm;
use crate::vtpm::tcgtpm::tss;

use crate::serial::{SerialPort, Terminal, DEFAULT_SERIAL_PORT};
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

pub static VTPM: SpinLock<Vtpm> = SpinLock::new(Vtpm::new());

/// Initialize the TPM by calling the init() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_init(manufacture: bool, tmc_array: &[u8; 8], is_pending: u8) -> Result<(), SvsmReqError> {
    detect_log!(info, "[detect] static cloning detection called, is_pending={}", is_pending);
    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(());
    }
    vtpm.init(manufacture)?;
    let vvtpm: &mut Vtpm = &mut *vtpm;
    let _ = tss::startup(vvtpm);

    // ========== Power-loss simulation using TPM NV ==========
    // Uses NV index 0x01c00002 to remember phase across reboots.
    // counter=0 (1st boot): write 1 → proceed normally
    // counter=1 (2nd boot): write 2 → panic (simulate power loss)
    // counter=2 (3rd boot): write 0 → proceed normally
    /*
    let power_sim_index: Vec<u8> = [0x01, 0xc0, 0x00, 0x02].to_vec();

    let counter: u64 = match tss::nvread(vvtpm, &power_sim_index) {
        Ok(nv_bytes) => extract_mc(&nv_bytes).unwrap(),
        Err(_) => {
            // NV index not defined yet → first ever boot, define it with counter=0
            let _ = tss::nvdefine(vvtpm, &power_sim_index, &"rw");
            let zero: [u8; 8] = [0; 8];
            _ = tss::nvwrite(vvtpm, &power_sim_index, &zero);
            0
        }
    };

    match counter {
        2 => {
            // 3rd boot: was 2 (crashed last time), reset to 0, proceed normally
            detect_log!(info, "[detect] Power-loss sim: 3rd boot (counter=2), resetting and proceeding normally.");
            let zero: [u8; 8] = [0; 8];
            _ = tss::nvwrite(vvtpm, &power_sim_index, &zero);
        }
        1 => {
            // 2nd boot: was 1 (passed normally last time), bump to 2, then panic
            detect_log!(info, "[detect] Power-loss sim: 2nd boot (counter=1), bumping to 2 and panicking...");
            let two: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
            _ = tss::nvwrite(vvtpm, &power_sim_index, &two);
            panic!("[detect] Simulated power loss! The VM will now crash and reboot.");
        }
        0 => {
            // 1st boot: bump to 1, proceed normally
            detect_log!(info, "[detect] Power-loss sim: 1st boot (counter=0), bumping to 1 and proceeding normally.");
            let one: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
            _ = tss::nvwrite(vvtpm, &power_sim_index, &one);
        }
        _ => {
            detect_log!(info, "[detect] Power-loss sim: unexpected counter={}, resetting and proceeding.", counter);
            let zero: [u8; 8] = [0; 8];
            _ = tss::nvwrite(vvtpm, &power_sim_index, &zero);
        }
    }
    */

    // 发送cap命令
    let  property = [0x01, 0x00, 0x00, 0x00].to_vec();
    let mut cap_resp = tss::getcap(vvtpm, &property)?;

    // Check if LMC is already defined (first boot vs reboot)
    let mut is_lmc_defined: Option<bool> = Some(false);
    let lmc_index:Vec<u8> = [0x01, 0xc0, 0x00, 0x01].to_vec();
    parse_getcap(&mut cap_resp, &mut is_lmc_defined, &lmc_index);
    match is_lmc_defined {
        Some(true) => {
            detect_log!(info, "[detect] LMC already defined, not first boot in normal mode");
        }
        Some(false) => {
            detect_log!(info, "[detect] LMC not defined, first boot in security mode");
        }
        _ => {
            detect_log!(info, "[detect] tpm nv parse error");
        }
    }
    
    // Validate
    match is_lmc_defined{
        Some(true) => {
            // read the old lmc, compare it with the new one, and write the new one
            let nv_bytes = tss::nvread(vvtpm, &lmc_index).unwrap();
            let lmc_u64: u64 = extract_mc(&nv_bytes).unwrap();
            let tmc_u64: u64 = u64::from_le_bytes(*tmc_array);
            detect_log!(info, "[detect] static check: LMC={}, TMC={}, is_pending={}", lmc_u64, tmc_u64, is_pending);
            if is_pending == 0 {
                // CLEAR state
                if tmc_u64 == lmc_u64 + 1 {
                    // c2: Normal Running
                    detect_log!(info, "[detect] c2: Normal reboot without attacks: old LMC={}, new TMC={}", lmc_u64, tmc_u64);
                    _ = tss::nvwrite(vvtpm, &lmc_index, &tmc_array);
                } else if tmc_u64 > lmc_u64 + 1 {
                    // c3: Cloning Attack Detected
                    detect_log!(error, "[detect] c3: Static Cloning attack detected! old LMC={}, new TMC={}.", lmc_u64, tmc_u64);
                    if verify_admin_passwd() {
                        // Admin unlocked — allow boot to proceed
                    } else {
                        detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
                    }
                } else {
                    // c1: Unreachable (M <= N, CLEAR)
                    detect_log!(error, "[detect] c1: Unreachable state (M<=N, CLEAR): LMC={}, TMC={}", lmc_u64, tmc_u64);
                    if verify_admin_passwd() {
                    } else {
                        detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
                    }
                }
            } else {
                // SET state
                if tmc_u64 == lmc_u64 + 2 || tmc_u64 == lmc_u64 + 1{
                    // c6: System Crash or Power Loss
                    detect_log!(warn, "[detect] c5/c6: System crash or power loss detected! LMC={}, TMC={}", lmc_u64, tmc_u64);
                    _ = tss::nvwrite(vvtpm, &lmc_index, &tmc_array);
                } else if tmc_u64 > lmc_u64 + 2 {
                    // c7: Disguised Cloning Attack
                    detect_log!(error, "[detect] c7: Disguised cloning attack detected! LMC={}, TMC={}", lmc_u64, tmc_u64);
                    if verify_admin_passwd() {
                    } else {
                        detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
                    }
                } else {
                    // c4: Unreachable (M <= N, SET)
                    detect_log!(error, "[detect] c4: Unreachable state (M<=N+1, SET): LMC={}, TMC={}", lmc_u64, tmc_u64);
                    if verify_admin_passwd() {
                    } else {
                        detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
                    }
                }
            }
        }
        Some(false) => {
            detect_log!(info, "[detect] Normal first boot, registering LMC=[{:?}] into the CVM", &tmc_array);
            let _ = tss::nvdefine(vvtpm, &lmc_index, &"rw");
            _ = tss::nvwrite(vvtpm, &lmc_index, &tmc_array);
        }
        _ => {
            detect_log!(info, "[detect] parse error");
        }
    }
    // post check (nvindex situation)
    // property = [0x01, 0x00, 0x00, 0x00].to_vec();
    // cap_stream = tss::getcap(vvtpm, &property)?;
    // parse_getcap(&mut cap_stream, &mut None, &extend_index, &mut None, &counter_index);

    Ok(())
}

/// Block and read a line from the serial console. Returns the entered password string.
/// Supports backspace for editing.
fn read_serial_line() -> String {
    let serial: &SerialPort<'_> = &DEFAULT_SERIAL_PORT;
    let mut input: [u8; 64] = [0; 64];
    let mut pos = 0;

    loop {
        let byte = Terminal::get_byte(serial);
        match byte {
            b'\r' | b'\n' => break,
            b'\x08' | b'\x7f' => {
                // Backspace / DEL
                if pos > 0 {
                    pos -= 1;
                    Terminal::put_byte(serial, b'\x08');
                    Terminal::put_byte(serial, b' ');
                    Terminal::put_byte(serial, b'\x08');
                }
            }
            _ if pos < input.len() - 1 && byte.is_ascii_graphic() => {
                input[pos] = byte;
                pos += 1;
                Terminal::put_byte(serial, byte); // echo
            }
            // silently ignore other control chars
            _ => {}
        }
    }

    Terminal::put_byte(serial, b'\r');
    Terminal::put_byte(serial, b'\n');

    String::from(core::str::from_utf8(&input[..pos]).unwrap_or(""))
}

/// Verify the admin key entered via serial console.
/// Blocks until the user provides input, then compares against the secret.
fn verify_admin_passwd() -> bool {
    const ADMIN_KEY: &str = "root";

    detect_log!(info, "[detect] System locked. Enter admin key to unlock:");
    let entered = read_serial_line();

    if entered == ADMIN_KEY {
        detect_log!(info, "[detect] Admin key accepted. Resuming normal operation.");
        true
    } else {
        detect_log!(error, "[detect] Invalid admin key '{}'. Access denied.", entered);
        false
    }
}

fn extract_mc(bytes: &Vec<u8>) -> Result<u64, SvsmReqError> {
    let tag = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let param_area_start = if tag == 0x8002 {
    // 带会话：跳过10B header + 4B parameterSize
        10 + 4
    } else {
    // 无会话：header之后直接参数
        10
    };

    let nv_len = u16::from_be_bytes(bytes[param_area_start..param_area_start+2].try_into().unwrap()) as usize;
    let nv_data = &bytes[param_area_start+2 .. param_area_start+2 + nv_len];
    // convert to u64 (le)
    let array = nv_data.try_into().map_err(|_e| SvsmReqError::invalid_request())?;
    Ok(u64::from_le_bytes(array))
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

fn parse_getcap(cap_stream : &mut Vec<u8>, is_defined :&mut Option<bool>, check_index: &Vec<u8>){
    const BOUND:usize = 19;

    if cap_stream.len() < BOUND{
        verbose_log!(info, "[vtpm-getcap] insufficient getcap resp length, error!");
        return
    }else if cap_stream.len() == BOUND{
        verbose_log!(info, "[vtpm-getcap] no payload!");
        return
    }

    let index_count = cap_stream[15..BOUND].to_vec();
    let num = u32::from_be_bytes(index_count.try_into().unwrap());
    let rest = cap_stream.split_off(BOUND);
    verbose_log!(info, "[vtpm-getcap] nv_index is {}, data_area is {:02x?}" , num, rest);
    for chunk in rest.chunks_exact(4) {
        let old_index: Vec<u8> = chunk.try_into().unwrap();
        if old_index == *check_index {
            verbose_log!(info, "[vtpm-getcap] index[0x{:02x?}] has been existed, stop repeated nv-creation!", old_index);
            if is_defined.is_some() {
               *is_defined = Some(true);
            }
            continue;
        }
    }
}

// SPDX-License-Identifier: MIT
//
// Dynamic Detection Protocol — CVM triggers detection via VMGEXIT

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Global flag: when set, the dynamic detection will simulate a power loss
/// (soft power-off) after completing its checks.
static SIMULATE_POWER_LOSS: AtomicBool = AtomicBool::new(false);

pub fn set_simulate_power_loss(flag: bool) {
    SIMULATE_POWER_LOSS.store(flag, Ordering::SeqCst);
}

fn get_simulate_power_loss() -> bool {
    SIMULATE_POWER_LOSS.load(Ordering::SeqCst)
}

use crate::attest::ATTESTATION_DRIVER;
use crate::error::SvsmError;
use crate::verbose_log as detect_log;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::serial::{SerialPort, Terminal, DEFAULT_SERIAL_PORT};
use crate::vtpm::tcgtpm::tss;
use crate::vtpm::tcgtpm::TcgTpm as Vtpm;
use crate::vtpm::VTPM;

// const SVSM_DETECT_DO_CHECK: u32 = 0;

// Called from vtpm_command_request when CC == TPM_CC_MyCmd (Switch to custom protocol later)
// pub fn detect_protocol_request(
//     request: u32,
//     _params: &mut RequestParams,
// ) -> Result<(), SvsmReqError> {
//     match request {
//         SVSM_DETECT_DO_CHECK => {
//             do_dynamic_detection();
//             Ok(())
//         }
//         _ => Err(SvsmReqError::unsupported_call()),
//     }
// }

pub fn trigger_dynamic_detection() {
    detect_log!(info, "[detect] dynamic cloning detection called");
    do_dynamic_detection();
}

fn do_dynamic_detection() {
    let lmc_index: Vec<u8> = [0x01, 0xc0, 0x00, 0x01].to_vec();

    // Step 1: read LMC (fast, release VTPM lock immediately)
    let lmc_u64 = {
        let mut vtpm = VTPM.lock();
        let vvtpm: &mut Vtpm = &mut *vtpm;
        let lmc_bytes = match tss::nvread(vvtpm, &lmc_index) {
            Ok(b) => b,
            Err(e) => {
                detect_log!(info, "[detect] nvread failed: {:?}", e);
                return;
            }
        };
        match extract_mc(&lmc_bytes) {
            Ok(v) => v,
            Err(_) => {
                detect_log!(info, "[detect] extract_mc failed");
                return;
            }
        }
    };

    // Step 2: get TMC from KBS (slow serial I/O, VTPM lock NOT held)
    let (tmc_bytes, tmc_u64, is_pending): (Vec<u8>, u64, u8) = {
        let mut driver_lock = ATTESTATION_DRIVER.lock();
        let driver = match driver_lock.as_mut() {
            Some(d) => d,
            None => {
                detect_log!(info, "[detect] attestation driver not ready");
                return;
            }
        };
        match driver.resource() {
            Ok(secret) => {
                if secret.len() >= 9 {
                    let tmc_vec = secret[secret.len() - 9..secret.len() - 1].to_vec();
                    let is_pending = secret[secret.len() - 1];
                    let tmc_u =
                        u64::from_le_bytes(tmc_vec.as_slice().try_into().unwrap_or([0u8; 8]));
                    detect_log!(info, "[detect] is_pending: {}", is_pending);
                    (tmc_vec, tmc_u, is_pending)
                } else {
                    detect_log!(warn, "[detect] secret too short");
                    (Vec::new(), 0u64, 0u8)
                }
            }
            Err(e) => {
                detect_log!(info, "[detect] resource request failed: {:?}", e);
                (Vec::new(), 0u64, 0u8)
            }
        }
        // driver_lock dropped here
    };

    // Step 3: compare and update LMC (re-acquire VTPM lock, fast)
    let mut vtpm = VTPM.lock();
    let vvtpm: &mut Vtpm = &mut *vtpm;
    detect_log!(info, "[detect] dynamic check: LMC={}, TMC={}, is_pending={}", lmc_u64, tmc_u64, is_pending);
    if is_pending == 0 {
        // CLEAR state
        if tmc_u64 == lmc_u64 + 1 {
            // c2: Normal Running
            detect_log!(info, "[detect] c2: Normal: LMC={}, TMC={}", lmc_u64, tmc_u64);
            let tmc_array: [u8; 8] = tmc_bytes
                .as_slice()
                .try_into()
                .expect("tmc_bytes must be exactly 8 bytes");
            if let Err(e) = tss::nvwrite(vvtpm, &lmc_index, &tmc_array) {
                detect_log!(error, "[detect] nvwrite failed: {:?}", e);
            }
        } else if tmc_u64 > lmc_u64 + 1 {
            // c3: Cloning Attack Detected
            detect_log!(error, "[detect] c3: Clone attack detected! LMC={}, TMC={}.", lmc_u64, tmc_u64);
            if verify_admin_passwd() {
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
        if tmc_u64 == lmc_u64 + 2 || tmc_u64 == lmc_u64 + 1 {
            // c6: System Crash or Power Loss
            detect_log!(warn, "[detect] c5/c6: System crash or power loss detected! LMC={}, TMC={}", lmc_u64, tmc_u64);
            let tmc_array: [u8; 8] = tmc_bytes
                .as_slice()
                .try_into()
                .expect("tmc_bytes must be exactly 8 bytes");
            if let Err(e) = tss::nvwrite(vvtpm, &lmc_index, &tmc_array) {
                detect_log!(error, "[detect] nvwrite failed: {:?}", e);
            }
        } else if tmc_u64 > lmc_u64 + 2 {
            // c7: Disguised Cloning Attack
            detect_log!(error, "[detect] c7: Disguised cloning attack detected! LMC={}, TMC={}", lmc_u64, tmc_u64);
            if verify_admin_passwd() {
            } else {
                detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
            }
        } else {
            // c4: Unreachable (M < N+1, SET)
            detect_log!(error, "[detect] c4: Unreachable state (M<=N+1, SET): LMC={}, TMC={}", lmc_u64, tmc_u64);
            if verify_admin_passwd() {
            } else {
                detect_log!(error, "[detect] Admin authentication failed. System remains locked.");
            }
        }
    }

    // Step 4: if the simulate flag was set, perform a soft power-off.
    // This must happen before releasing KBS resources, so the power loss
    // is observed as an abrupt termination mid-detection.
    if get_simulate_power_loss() {
        detect_log!(info, "[detect] simulate flag set, performing soft power-off");
        crate::sev::msr_protocol::request_termination_msr();
    }

    // Step 5: notify KBS to release resources
    {
        let mut driver = ATTESTATION_DRIVER.lock();
        if let Some(driver) = driver.as_mut() {
            if let Err(e) = driver.release() {
                detect_log!(error, "[detect] release request failed: {:?}", e);
            }
        }
    }
}

fn extract_mc(bytes: &Vec<u8>) -> Result<u64, SvsmError> {
    let tag = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let param_area_start = if tag == 0x8002 {
        10 + 4
    } else {
        10
    };

    let nv_len =
        u16::from_be_bytes(bytes[param_area_start..param_area_start + 2].try_into().unwrap())
            as usize;
    let nv_data = &bytes[param_area_start + 2..param_area_start + 2 + nv_len];
    let nv_array: [u8; 8] = nv_data.try_into().map_err(|_e| SvsmError::InvalidBytes)?;
    let val = u64::from_le_bytes(nv_array);
    // detect_log!(info, "[detect] lmc_bytes is {:02x?}, lmc_u64 is {}", nv_array, val);
    Ok(val)
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
                Terminal::put_byte(serial, byte);
            }
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

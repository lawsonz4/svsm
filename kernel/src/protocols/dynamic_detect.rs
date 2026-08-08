// SPDX-License-Identifier: MIT
//
// Dynamic Detection Protocol — CVM triggers detection via VMGEXIT

extern crate alloc;

use alloc::vec::Vec;

/// Local verbose switch: true = print all [detect] logs (default on).
const DETECT_VERBOSE: bool = true;

macro_rules! detect_log {
    ($lvl:ident, $($arg:tt)*) => {
        if DETECT_VERBOSE {
            log::$lvl!($($arg)*);
        }
    };
}

use crate::attest::ATTESTATION_DRIVER;
use crate::error::SvsmError;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
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
    detect_log!(info, "[detect] dynamic detection called");
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
    let (tmc_bytes, tmc_u64): (Vec<u8>, u64) = {
        let mut guard = ATTESTATION_DRIVER.lock();
        let driver = match guard.as_mut() {
            Some(d) => d,
            None => {
                detect_log!(info, "[detect] attestation driver not ready");
                return;
            }
        };
        match driver.resource() {
            Ok(secret) => {
                if secret.len() >= 8 {
                    let tmc_vec = secret[secret.len() - 8..].to_vec();
                    let tmc_u =
                        u64::from_le_bytes(tmc_vec.as_slice().try_into().unwrap_or([0u8; 8]));
                    (tmc_vec, tmc_u)
                } else {
                    detect_log!(warn, "[detect] secret too short");
                    (Vec::new(), 0u64)
                }
            }
            Err(e) => {
                detect_log!(info, "[detect] resource request failed: {:?}", e);
                (Vec::new(), 0u64)
            }
        }
    };

    // Step 3: compare and update LMC (re-acquire VTPM lock, fast)
    let mut vtpm = VTPM.lock();
    let vvtpm: &mut Vtpm = &mut *vtpm;
    if tmc_u64 > lmc_u64 + 1 {
        panic!(
            "[detect] ATTACK: Trusted-MC={}, Local-MC={}",
            tmc_u64, lmc_u64
        );
    } else if tmc_u64 == lmc_u64 + 1 {
        detect_log!(info,
            "[detect] normal: TMC={}, LMC={}",
            tmc_u64, lmc_u64
        );
        let tmc_array: [u8; 8] = tmc_bytes
            .as_slice()
            .try_into()
            .expect("tmc_bytes must be exactly 8 bytes");
        if let Err(e) = tss::nvwrite(vvtpm, &lmc_index, &tmc_array) {
            detect_log!(error, "[detect] nvwrite failed: {:?}", e);
        }
    } else {
        detect_log!(info, "[detect] no change: TMC={}, LMC={}",
            tmc_u64, lmc_u64
        );
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
    detect_log!(info, "[detect] lmc_bytes is {:02x?}, lmc_u64 is {}", nv_array, val);
    Ok(val)
}

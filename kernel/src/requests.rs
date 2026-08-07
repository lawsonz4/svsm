// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::ipi::wait_for_ipi_block;
use crate::cpu::percpu::{this_cpu, PERCPU_AREAS};
use crate::protocols::apic::apic_protocol_request;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::task::{go_idle, set_affinity, start_kernel_thread};
use crate::vmm::{enter_guest, GuestExitMessage, GuestRegister};

use crate::protocols::attest::attest_protocol_request;
#[cfg(all(feature = "uefivars", not(test)))]
use crate::protocols::{uefivars::uefi_mm_protocol_request, SVSM_UEFI_MM_PROTOCOL};
#[cfg(all(feature = "vtpm", not(test)))]
use crate::protocols::{vtpm::vtpm_protocol_request, SVSM_VTPM_PROTOCOL};
use crate::protocols::{
    RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
};

#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
use crate::attest::ATTESTATION_DRIVER;
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
use crate::error::SvsmError;
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
use crate::vtpm::tcgtpm::tss;
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
use crate::vtpm::VTPM;
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
use crate::vtpm::tcgtpm::TcgTpm as Vtpm;

use alloc::vec::Vec;

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SvsmCaa {
    call_pending: u8,
    mem_available: u8,
    pub no_eoi_required: u8,
    _rsvd: [u8; 5],
}

impl SvsmCaa {
    /// Indicates whether the `call_pending` flag is set.
    #[inline]
    pub fn call_pending(&self) -> bool {
        self.call_pending != 0
    }

    /// Returns a copy of the this CAA with the `call_pending` field cleared.
    #[inline]
    pub const fn serviced(self) -> Self {
        Self {
            call_pending: 0,
            ..self
        }
    }

    /// Returns a copy of the this CAA with the `no_eoi_required` flag updated
    #[inline]
    pub const fn update_no_eoi_required(self, no_eoi_required: u8) -> Self {
        Self {
            no_eoi_required,
            ..self
        }
    }

    /// A CAA with all of its fields set to zero.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            call_pending: 0,
            mem_available: 0,
            no_eoi_required: 0,
            _rsvd: [0; 5],
        }
    }
}

const _: () = assert!(core::mem::size_of::<SvsmCaa>() == 8);

fn request_loop_once(
    params: &mut RequestParams,
    protocol: u32,
    request: u32,
) -> Result<(), SvsmReqError> {
    match protocol {
        SVSM_CORE_PROTOCOL => core_protocol_request(request, params),
        SVSM_ATTEST_PROTOCOL => attest_protocol_request(request, params),
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_VTPM_PROTOCOL => vtpm_protocol_request(request, params),
        SVSM_APIC_PROTOCOL => apic_protocol_request(request, params),
        #[cfg(all(feature = "uefivars", not(test)))]
        SVSM_UEFI_MM_PROTOCOL => uefi_mm_protocol_request(request, params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub extern "C" fn request_loop_main(cpu_index: usize) {
    log::info!("Launching request-processing task on CPU {}", cpu_index);

    if cpu_index != 0 {
        // Send this task to the correct CPU.
        set_affinity(cpu_index);
    } else {
        // When starting the request loop on the BSP, start an additional
        // request loop task for each other processor in the system.
        let cpu_count = PERCPU_AREAS.len();
        for task_index in 1..cpu_count {
            start_kernel_thread(request_loop_main, task_index)
                .expect("Failed to launch request loop thread");
        }
    }

    debug_assert_eq!(cpu_index, this_cpu().get_cpu_index());

    // Suppress the use of IPIs before entering the guest, and ensure that all
    // other CPUs have done the same.
    wait_for_ipi_block();

    let mut guest_regs = Vec::<GuestRegister>::new();

    loop {
        // Attempt to enter the guest.  Once registers have been set, reset the
        // vector so they are not set again.
        let msg = enter_guest(guest_regs.as_slice());
        guest_regs = Vec::new();

        match msg {
            GuestExitMessage::NoMappings => {
                log::debug!("No VMSA or CAA! Halting");
                go_idle();
            }
            GuestExitMessage::Svsm((protocol, request, mut params)) => {
                guest_regs = process_request(protocol, request, &mut params);
            }
        }
    }
}

fn process_request(protocol: u32, request: u32, params: &mut RequestParams) -> Vec<GuestRegister> {
    let rax: Option<u64> = match request_loop_once(params, protocol, request) {
        Ok(()) => Some(SvsmResultCode::SUCCESS.into()),
        Err(SvsmReqError::RequestError(code)) => {
            log::debug!(
                "Soft error handling protocol {} request {}: {:?}",
                protocol,
                request,
                code
            );
            Some(code.into())
        }
        Err(SvsmReqError::FatalError(err)) => {
            panic!(
                "Fatal error handling core protocol request {}: {:?}",
                request, err
            )
        }
    };

    // Generate vector of registers to update.
    let mut guest_regs = Vec::<GuestRegister>::new();
    if let Some(val) = rax {
        guest_regs.push(GuestRegister::X64Rax(val));
    }

    params.capture(&mut guest_regs);

    guest_regs
}

// ===========================================================================
// Dynamic Detection — runs inline in request_loop_main on every VMGEXIT
// ===========================================================================

/// Set to false to silence all detection logs (panic still fires).
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
const DETECT_VERBOSE: bool = false;

/// Wrapper: only emits log when DETECT_VERBOSE is true.
#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
macro_rules! detect_log {
    ($lvl:ident, $($arg:tt)*) => {
        if DETECT_VERBOSE {
            log::$lvl!($($arg)*);
        }
    };
}

#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
fn run_dynamic_detection(count: u64) {
    let lmc_index: Vec<u8> = [0x01, 0xc0, 0x00, 0x01].to_vec();

    let mut vtpm = VTPM.lock();
    let vvtpm: &mut Vtpm = &mut *vtpm;

    let lmc_bytes = match tss::nvread(vvtpm, &lmc_index) {
        Ok(b) => b,
        Err(e) => {
            detect_log!(info, "[detect] nvread failed (count={}): {:?}", count, e);
            return;
        }
    };
    let lmc_u64 = match extract_mc_req(&lmc_bytes) {
        Ok(v) => v,
        Err(_) => {
            detect_log!(info, "[detect] extract_mc failed (count={})", count);
            return;
        }
    };

    let (tmc_bytes, tmc_u64): (Vec<u8>, u64) = {
        let mut guard = ATTESTATION_DRIVER.lock();
        let driver = match guard.as_mut() {
            Some(d) => d,
            None => {
                detect_log!(info, "[detect] attestation driver not ready (count={})", count);
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
                    detect_log!(warn, "[detect] secret too short (count={})", count);
                    (Vec::new(), 0u64)
                }
            }
            Err(e) => {
                detect_log!(info, "[detect] resource request failed (count={}): {:?}", count, e);
                (Vec::new(), 0u64)
            }
        }
    };

    if tmc_u64 > lmc_u64 + 1 {
        panic!(
            "[detect] ATTACK: Trusted-MC={}, Local-MC={} (count={})",
            tmc_u64, lmc_u64, count
        );
    } else if tmc_u64 == lmc_u64 + 1 {
        detect_log!(info,
            "[detect] normal: TMC={}, LMC={} (count={})",
            tmc_u64, lmc_u64, count
        );
        let tmc_array: [u8; 8] = tmc_bytes
            .as_slice()
            .try_into()
            .expect("tmc_bytes must be exactly 8 bytes");
        if let Err(e) = tss::nvwrite(vvtpm, &lmc_index, &tmc_array) {
            detect_log!(error, "[detect] nvwrite failed (count={}): {:?}", count, e);
        }
    } else {
        // Throttled: only log "no change" periodically when verbose
        if DETECT_VERBOSE && count % 50 == 0 {
            log::info!(
                "[detect] no change (x{}): TMC={}, LMC={}",
                count, tmc_u64, lmc_u64
            );
        }
    }
}

#[cfg(all(feature = "attest", feature = "vtpm", not(test)))]
fn extract_mc_req(bytes: &Vec<u8>) -> Result<u64, SvsmError> {
    let tag = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let param_area_start = if tag == 0x8002 {
        // With session: skip 10B header + 4B parameterSize
        10 + 4
    } else {
        // Without session: params right after header
        10
    };

    let nv_len =
        u16::from_be_bytes(bytes[param_area_start..param_area_start + 2].try_into().unwrap())
            as usize;
    let nv_data = &bytes[param_area_start + 2..param_area_start + 2 + nv_len];
    let array: [u8; 8] = nv_data.try_into().map_err(|_e| SvsmError::InvalidBytes)?;
    let val = u64::from_le_bytes(array);
    detect_log!(info, "[detect] lmc_bytes={:02x?}, lmc_u64={}", array, val);
    Ok(val)
}
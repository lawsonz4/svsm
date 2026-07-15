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
use alloc::string::String;

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
pub fn vtpm_init(manufacture: bool, tmc_array: &[u8; 8]) -> Result<(), SvsmReqError> {
    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(());
    }
    vtpm.init(manufacture)?;
    let vvtpm: &mut Vtpm = &mut *vtpm;
    let _ = tss::startup(vvtpm);
    // 发送cap命令
    let  property = [0x01, 0x00, 0x00, 0x00].to_vec();
    let mut cap_resp = tss::getcap(vvtpm, &property)?;

    // 检查lmc是否已定义（是否初次启动）
    let mut is_lmc_defined: Option<bool> = Some(false);
    let lmc_index:Vec<u8> = [0x01, 0xc0, 0x00, 0x01].to_vec();
    parse_getcap(&mut cap_resp, &mut is_lmc_defined, &lmc_index);
    match is_lmc_defined {
        Some(true) => {
            log::info!("[vtpm] lmc 已定义，不是初次启动");
        }
        Some(false) => {
            log::info!("[vtpm] lmc 尚未定义，是初次启动");
        }
        _ => {
            log::info!("[vtpm] parse error");
        }
    }
    
    // 校验
    match is_lmc_defined{
        Some(true) => {
            // read the old lmc, compare it with the new one, and write the new one
            let resp_bytes = tss::nvread(vvtpm, &lmc_index).unwrap();
            let mut lmc_u64: u64 = extract_mc(&resp_bytes).unwrap();
    let mut tmc_u64: u64 = u64::from_ne_bytes(*tmc_array);
            if tmc_u64 != lmc_u64 +1 {
                log::info!("[vtpm] 异常非初次启动，已遭受克隆攻击，旧的lmc u64 is {}, 新的tmc u64 is {}", &lmc_u64, &tmc_u64);
                // let is_admin = verify_admin_passwd();
                // if !is_admin{
                return Err(SvsmReqError::invalid_request())
            }else{
                log::info!("[vtpm] 正常非初次启动，旧的lmc u64 is {}, 新的tmc u64 is {}", &lmc_u64, &tmc_u64);
                _ = tss::nvwrite(vvtpm, &lmc_index, &tmc_array);
            }
        }
        Some(false) => {
            log::info!("[vtpm] 正常初次启动，register lmc[{:?}] into the cvm", &tmc_array);
            let _ = tss::nvdefine(vvtpm, &lmc_index, &"rw");
            _ = tss::nvwrite(vvtpm, &lmc_index, &tmc_array);
        }
        _ => {
            log::info!("[vtpm] parse error");
        }
    }
    // post (nvindex situation) check
    // property = [0x01, 0x00, 0x00, 0x00].to_vec();
    // cap_stream = tss::getcap(vvtpm, &property)?;
    // parse_getcap(&mut cap_stream, &mut None, &extend_index, &mut None, &counter_index);

    Ok(())
}

// // TODO：svsm有无串口输入?
// fn verify_admin_passwd() -> bool{
//     const PWD_CORRECT: &str = "root";

//     let mut input = String::new();
//     // 读取一行用户输入
//     io::stdin()
//         .read_line(&mut input)
//         .expect("读取输入失败");

//     // 剔除末尾换行符 \n / \r\n
//     let input = input.trim();

//     if input == PWD_CORRECT {
//         true
//     } else {
//         false
//     }
// }

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
    // convert to u64 (ne)
    let array = nv_data.try_into().map_err(|_e| SvsmReqError::invalid_request())?;
    Ok(u64::from_ne_bytes(array))
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
        log::info!("[vtpm-parse-getcap] insufficient getcap resp length, error!");
        return
    }else if cap_stream.len() == BOUND{
        log::info!("[vtpm-parse-getcap] no payload!");
        return
    }

    let index_count = cap_stream[15..BOUND].to_vec();
    let num = u32::from_be_bytes(index_count.try_into().unwrap());
    let rest = cap_stream.split_off(BOUND);
    log::info!("[vtpm-parse-getcap] nv_index_num is {}, data area is {:02x?}" , num, rest);
    for chunk in rest.chunks_exact(4) {
        let old_index: Vec<u8> = chunk.try_into().unwrap();
        if old_index == *check_index {
            log::info!("[vtpm-parse-getcap] index[0x{:02x?}] has been existed, stop repeated nv-creation!", old_index);
            if is_defined.is_some() {
               *is_defined = Some(true);
            }
            continue;
        }
    }
}

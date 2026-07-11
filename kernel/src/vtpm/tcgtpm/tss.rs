// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025  Hewlett Packard Enterprise Development LP
// Copyright (c) Coconut-SVSM authors
//

// This module is an incomplete software stack for constructing commands to send to the TPM.
// It is not fully general for expressing all inputs to a command.

extern crate alloc;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::{
    tcgtpm::{TcgTpmSimulatorInterface, TPM_BUFFER_MAX_SIZE},
    SvsmVTpmError,
};
use alloc::vec::Vec;

pub const TPM_RC_SUCCESS: u32 = 0;

// PREREQUISITE: CMD must be at least 10 bytes long.
// A TPM command result contains
//
// Byte offset | Size | Description
// ---
// 0x00        | 2    | u16 ST tag
// 0x02        | 4    | u32 response size
// 0x06        | 4    | u32 response code
fn tpm_cmd_rc(cmd: &[u8]) -> u32 {
    u32::from_be_bytes(cmd[6..10].try_into().unwrap())
}

fn extend_empty_auth(buf: &mut Vec<u8>) {
    // TPM_RS_PW(4) + nonce(2) + attributes(1) + pw(2)
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x09, // Size
        0x40, 0x00, 0x00, 0x09, // TPM_RS_PW 密码句柄
        0x00, 0x00, // nonce == empty buffer
        0x01, // session attributes = continueSession = 0x01
        0x00, 0x00, // password = empty buffer
    ]);
}

fn create_mtauth_ek_cmd(tpmt_public: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    // TPM Command header
    cmd.extend_from_slice(&[
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x00, // Placeholder for command size
        0x00, 0x00, 0x01, 0x31, // TPM_CC_CREATEPRIMARY
        0x40, 0x00, 0x00, 0x0B, // TPM_RH_ENDORSEMENT
    ]);

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive parameter
    //
    // TPM2B_SENSITIVE_CREATE structure is defined in
    // Table 132 — Definition of TPM2B_SENSITIVE_CREATE Structure,
    // Trusted Platform Module Library Part 2: Structures
    cmd.extend_from_slice(&[
        0x00, 0x04, // sensitive data size
        0x00, 0x00, 0x00, 0x00, // user auth
    ]);

    // inPublic parameter
    // parameters size
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    // parameters
    cmd.extend_from_slice(tpmt_public);

    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // outsideInfo parameter
        0x00, 0x00, // pcr selection
    ]);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

// how to calculate?
#[warn(dead_code)]
fn get_hmac_auth() -> Vec<u8>{
    Vec::<u8>::new()
}

fn start_authsession_cmd() -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        // === 头部 ===
        0x80, 0x01,                     // tag: TPM_ST_NO_SESSIONS (0x8001)
        0x00, 0x00, 0x00, 0x3b,         // commandSize: 59 (0x3b)
        0x00, 0x00, 0x01, 0x76,         // commandCode: TPM2_StartAuthSession (0x176)

        // === 参数 ===
        0x40, 0x00, 0x00, 0x07,         // tpmKey: TPM_RH_NULL (0x40000007)
        0x40, 0x00, 0x00, 0x07,         // bind: TPM_RH_NULL (0x40000007)
        0x00, 0x20,                     // nonceCaller.size: 32 bytes
        // NonceCaller
        0xd3, 0x74, 0x46, 0xa6, 0xc2, 0x99, 0xca, 0x3f,
        0x7e, 0xd0, 0xb9, 0xf9, 0x85, 0x19, 0x58, 0x60,
        0x50, 0xbb, 0xc7, 0xdc, 0x00, 0x56, 0x49, 0xfe,
        0xe6, 0x48, 0x12, 0xce, 0x52, 0xb8, 0xd1, 0x2a,

        // === 会话参数 ===
        0x00, 0x00,                     // encryptedSalt(TPM2B_EMPTY)
        0x00,                           // sessionType: TPM_SE_HMAC (0x00)
        0x00, 0x10,                     // symmetric.algorithm: TPM_ALG_NULL (0x0010)
        0x00, 0x0b                     // authHash: TPM_ALG_SHA256 (0x000b)
    ]);
    cmd
}

fn startup_cmd() -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
    0x80, 0x01, //ST
    0x00, 0x00, 0x00, 0x0c, //SIZE
    0x00, 0x00, 0x01, 0x44, //CC
    0x00, 0x00 // startup type：clear
    ]);
    return cmd
}

fn getcap_cmd(property: &Vec<u8>) -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        0x80, 0x01, //ST
        0x00, 0x00, 0x00, 0x16, // CS=22
        0x00, 0x00, 0x01, 0x7a, //CC
        0x00, 0x00, 0x00, 0x01, // TPM_CAP
    ]);
    cmd.extend_from_slice(property);
    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0xfe // propertyCount
    ]);
    cmd
}

fn flushctx_cmd() -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        0x80, 0x01, //ST
        0x00, 0x00, 0x00, 0x16, // CS=22
        0x00, 0x00, 0x01, 0x7a, //CC
        0x00, 0x00, 0x00, 0x01, // TPM_CAP
        0x01, 0x00, 0x00, 0x00, // further property
        0x00, 0x00, 0x00, 0xfe // propertyCount
    ]);
    cmd
}

fn nvdefine_cmd(index :&Vec<u8>, nvtype : &str) -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    // 首部
    cmd.extend_from_slice(&[
        0x80, 0x02, //ST
        0x00, 0x00, 0x00, 0x00, //CS placeholder
        0x00, 0x00, 0x01, 0x2a //CC
    ]);
    // 句柄区
    cmd.extend_from_slice(&[ 
        0x40, 0x00, 0x00, 0x01 //TPM_RH_OWNER
    ]);
    // 认证区
    extend_empty_auth(&mut cmd);
    // 参数区：NVTemplate
    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x0e, //template size=14 
    ]);
    cmd.extend_from_slice(index); // NVIndex
    if nvtype == "extend"{
        cmd.extend_from_slice(&[
            0x00, 0x0b, // nameALG=SHA256
            // 0x00, 0x04, 0x00, 0x44, // nv attr:authread&authwrite
            0x00, 0x02, 0x00, 0x42,// nv attr:ownerread&ownerwrite
            0x00, 0x00, // AuthPolicy
            0x00, 0x20 // datasize   
        ]);
    }else if nvtype == "counter"{
        cmd.extend_from_slice(&[
            0x00, 0x0b, // nameALG=SHA256
            // 0x00, 0x04, 0x00, 0x44, // nv attr:authread&authwrite
            0x00, 0x02, 0x00, 0x12,// nv attr:ownerread&ownerwrite
            0x00, 0x00, // AuthPolicy
            0x00, 0x08 // datasize   
        ]);
    }
    return cmd
}

fn nvextend_cmd(index :&Vec<u8>) -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        0x80, 0x02, //ST
        0x00, 0x00, 0x00, 0x00, // placeholder
        0x00, 0x00, 0x01, 0x36 // CC=TPM2_NV_EXTEND
    ]);
    // 
    cmd.extend_from_slice(&[ 
        0x40, 0x00, 0x00, 0x01 // Auth Handle:TPM_RH_OWNER
    ]);
    cmd.extend_from_slice(&index); // NV_INDEX
    extend_empty_auth(&mut cmd); // empty auth area
    // ===NV Buffer===/
    cmd.extend_from_slice(&[
        0x00, 0x06, // size=6
        0x6d, 0x79, 0x64, 0x61, 0x74, 0x61// "mydata"
    ]);
    return cmd
}

#[warn(dead_code)]
fn createprimary_cmd() -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        0x80, 0x02, //ST
        0x00, 0x00, 0x00, 0x46, // placeholder
        0x00, 0x00, 0x01, 0x31 // CC=TPM2_CREATEPRIMARY
    ]);
    // 
    cmd.extend_from_slice(&[ 
        0x40, 0x00, 0x00, 0x01 // Auth Handle:TPM_RH_OWNER
    ]);
    extend_empty_auth(&mut cmd); // empty auth area
    
    cmd.extend_from_slice(&[
        0x00, 0x07, // inSensitive
        0x00, 0x03,
        0x73, 0x74, 0x6f, 
        0x00, 0x00// "mydata"
    ]);

    cmd.extend_from_slice(&[
        // inPublic
        0x00, 0x1a,
        0x00, 0x23,
        0x00, 0x12, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 
        0x00, 0x13, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x20, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    return cmd
}

fn nvincrement_cmd(index :&Vec<u8>) -> Vec<u8>{
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
    cmd.extend_from_slice(&[
        0x80, 0x02, //ST
        0x00, 0x00, 0x00, 0x00, // placeholder
        0x00, 0x00, 0x01, 0x34 // CC=TPM2_NV_INCREMENT
    ]);
    // 
    cmd.extend_from_slice(&[ 
        0x40, 0x00, 0x00, 0x01 // Auth Handle:TPM_RH_OWNER
    ]);
    cmd.extend_from_slice(&index); // NV_INDEX
    extend_empty_auth(&mut cmd); // empty auth area
    return cmd
}

/// Sends `cmd` to `vtpm` and returns the interpretation of its error mode.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `cmd`: A command buffer.
/// * `set_len`: If true, sets the command length in the command header to `cmd.len()` before
///   sending the command.
///
/// Returns:
///
/// The command response on success, or an error.
pub fn checked_send<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    cmd: &mut [u8],
    set_len: bool,
) -> Result<Vec<u8>, SvsmVTpmError> {
    let command_size;
    if set_len {
        command_size = cmd.len();
        cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());
    } else {
        command_size = u32::from_be_bytes(cmd[2..6].try_into().unwrap()) as usize;
    }
    log::info!("[vtpm-stream] sending cmd is {:02x?}", &cmd);
    let response = vtpm
        .send_tpm_command(&cmd[..command_size], 0)
        .map_err(|_| SvsmVTpmError::ReqError(SvsmReqError::invalid_request()))?;
    log::info!("[vtpm-stream] received resp is: {:02x?}", response);

    let rc = tpm_cmd_rc(&response);
    if rc != TPM_RC_SUCCESS {
        log::info!("[vtpm-stream] execute this cmd success");
        return Err(SvsmVTpmError::CommandError(rc));
    }
    log::info!("[vtpm-stream] execute this cmd fail");
    Ok(response)
}

/// Uses `vtpm` to create an a primary key on the endorsement hierarchy.
///
/// The key has no authorization policy.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `tpmt_public`: A marshaled TPMT_PUBLIC to use as the key creation template.
///
/// Returns:
///
/// A TPMT_PUBLIC of the key created from the template.
pub fn create_ek<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    tpmt_public: &[u8],
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = create_mtauth_ek_cmd(tpmt_public);

    let mut response = checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;

    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    let size_of_tpmt_public = u16::from_be_bytes([response[18], response[19]]) as usize;
    Ok(response.drain(20..(20 + size_of_tpmt_public)).collect())
}

pub fn nvdefine<T: TcgTpmSimulatorInterface>(
    vtpm: &T, index : &Vec<u8>, nvtype: &str
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = nvdefine_cmd(&index, &nvtype);
    let resp = checked_send(vtpm, &mut cmd, true)?;
    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    log::info!("[tpm2_nvdefine] response is: {:02x?}", resp);
    Ok(resp)
}

pub fn start_authsession<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = start_authsession_cmd();
    let resp = checked_send(vtpm, &mut cmd, /*set_len=*/ true)?;
    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    log::info!("[tpm2_startauthsession] response is: {:02x?}", resp);
    Ok(resp)
}


pub fn startup<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = startup_cmd();
    let resp = checked_send(vtpm, &mut cmd, true)?;
    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    log::info!("[tpm2_startup] response is: {:02x?}", resp);
    Ok(resp)
}

pub fn getcap<T: TcgTpmSimulatorInterface>(
    vtpm: &T, property :&Vec<u8>
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = getcap_cmd(property);
    let resp = checked_send(vtpm, &mut cmd, true)?;
    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    log::info!("[tpm2_getcap] response is: {:02x?}", resp);
    Ok(resp)
}

pub fn nvextend<T: TcgTpmSimulatorInterface>(
    vtpm: &T, index : &Vec<u8>
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = nvextend_cmd(&index);
    let resp = checked_send(vtpm, &mut cmd, true)?;
    log::info!("[tpm2_nvextend] response is: {:02x?}", resp);
    Ok(resp)
}

pub fn nvincrement<T: TcgTpmSimulatorInterface>(
    vtpm: &T, index : &Vec<u8>
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = nvincrement_cmd(&index);
    let resp = checked_send(vtpm, &mut cmd, true)?;
    log::info!("[tpm2_increment] response is: {:02x?}", resp);
    Ok(resp)
}
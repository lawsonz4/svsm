// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::{anyhow, Context};
use kbs15::*;
use reqwest::StatusCode;
use serde::{Deserialize};
use serde_json::{Value};
use libaproxy::*;
use base64::{
    prelude::{BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use std::sync::Mutex;

static ATTESTATION_TOKEN: Mutex<Option<String>> = Mutex::new(None);

fn set_attestation_token(token: String) {
    let mut guard = ATTESTATION_TOKEN.lock().expect("failed to lock attestation token storage");
    *guard = Some(token);
}

fn get_attestation_token() -> Option<String> {
    let guard = ATTESTATION_TOKEN.lock().expect("failed to lock attestation token storage");
    guard.clone()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TrusteeProtocol;

impl AttestationProtocol for TrusteeProtocol {
    /// KBS servers usually want two components hashed into attestation evidence: the public
    /// components of the TEE key, and a nonce provided in the KBS challenge that is fetched
    /// from the server's /auth endpoint. These must be hased in order.
    ///
    /// Make this request to /auth, gather the nonce, and return this in the negotiation
    /// parameter for SVSM to hash these components in the attestation evidence.
    fn negotiation(
        &mut self,
        http: &mut HttpClient,
        request: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        if request.version != *"0.4.0" {
            return Err(anyhow!("invalid request version"));
        }
        let req = Request {
            version: "0.4.0".to_string(), // unused.
            tee: request.tee,
            extra_params: Value::String("".to_string()), // unused.
        };

        println!("[aproxy-protocol] req of /atuth is:\n{}", serde_json::to_string(&req).unwrap());
        // Fetch challenge containing a nonce from the KBS /auth endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/auth", http.url))
            .json(&req)
            .send()
            .map_err(|e| {
                if e.is_connect() {
            println!("[aproxy-error] 无法建立 TCP 连接（检查 KBS 进程是否启动、端口/网络隔离）: {e}");
        } else if e.is_timeout() {
            println!("[aproxy-error] 请求 KBS 超时（检查防火墙或网络延迟）: {e}");
        } else if e.is_builder() {
            println!("[aproxy-error] 构建请求失败（URL 格式或 Header 非法）: {e}");
        } else if e.is_request() {
            println!("[aproxy-error] 发送请求过程中出错: {e}");
        }

        // 3. 打印深层错误链 (Cause Chain)
        let mut source = std::error::Error::source(&e);
        let mut depth = 1;
        while let Some(err) = source {
            println!("[aproxy-error]  └─ Cause {depth}: {err}");
            source = err.source();
            depth += 1;
        }
        e
            })
            .context("unable to POST to KBS /auth endpoint")?;


        let text = http_resp
            .text()
            .context("unable to convert KBS /auth response to text")?;
        println!("[aproxy-protocol] resp of /auth is:\n{}", text);

        let challenge: Challenge =
            serde_json::from_str(&text).context("unable to convert KBS /auth response to JSON")?;

        // Challenge nonce is a base64-encoded byte vector. Inform SVSM of this so it could
        // decode the bytes and hash them into the TEE evidence.
        let params = vec![
            NegotiationParam::EcPublicKeyBytes,
            NegotiationParam::Base64StdBytes(challenge.nonce),
        ];

        let resp = NegotiationResponse { params };

        Ok(resp)
    }

    /// With the serialized TEE evidence and key, complete the attestation. Serialize the evidence
    /// and send it to the /attest endpoint of the KBS server. Upon a successful attestation, fetch
    /// a secret (identified as "svsm_secret"). If able to successfully fetch the secret, return a
    /// successful AttestationResponse with the secret included.
    fn attestation(
        &mut self,
        http: &mut HttpClient,
        request: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {

        // Create a KBS attestation object from the TEE evidence and key.
        let attestation = Attestation {
            init_data: None,
            runtime_data: RuntimeData {
                nonce: request.nonce,
                tee_pubkey: request.key.into(),
            },
            tee_evidence: CompositeEvidence {
                primary_evidence: Value::String(request.evidence),
                additional_evidence: String::from(""),
            },
        };

        println!("[aproxy-protocol] req struct of /attest is:\n{:?}", &attestation);
        let attestation_bytes = serde_json::to_vec(&attestation).context("serialize attestation")?;
        println!("[aproxy-protocol] req bytes of /attest is:\n{:?}", &attestation_bytes);

        // Attest TEE evidence at KBS /attest endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/attest", http.url))
            .header("Content-Type", "application/json")
            .body(attestation_bytes)
            // .json(&attestation)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;


        // The JSON response from the /attest endpoint is basically ignored here. Instead, we check
        // the HTTP status to indicate successful attestation.
        //
        // FIXME
        // if http_resp.status() != StatusCode::OK {
        //     return Ok(AttestationResponse {
        //         success: false,
        //         secret: None,
        //         pub_key: None,
        //     });
        // }

        println!("[aproxy-protocol] resp header of /attest is:\n{:?}", &http_resp);
        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
            });
        }
        //读body(just for debug)
        let body_bytes = http_resp
            .bytes()
            .context("unable to read KBS /resource response")?;
        println!("[aproxy-protocol] resp bytes of /attest is:\n{:?}", &body_bytes);
        // 反序列化(just for debug)
        let resp_struct: TokenResponse = serde_json::from_slice(&body_bytes).unwrap();
        println!("[aproxy-protocol] resp body of /attest is:\n{:?}", &resp_struct);

        set_attestation_token(resp_struct.token.clone());

        // 请求资源作为 attestation 流程的一部分（可选），并保留 token 供后续 resource 接口使用。
        let http_resp = http
            .cli
            .get(format!("{}/kbs/v0/resource/lawson/secret/cvm0", http.url))
            .bearer_auth(&resp_struct.token)
            .send()
            .context("unable to GET KBS /resource endpoint after attest")?;
        println!("[aproxy-protocol] resp header of lawson/secret/cvm0 is:\n{:?}", &http_resp);

        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
            });
        }
        let body_bytes = http_resp
            .bytes()
            .context("unable to read KBS /resource response")?;
        let resp_struct: Response = serde_json::from_slice(&body_bytes).unwrap();
        println!("[aproxy-protocol] resp body of lawson/secret/cvm0 is:\n{:?}", &resp_struct);

        let epk = unwrap_epk(&resp_struct)?;
        let aad = resp_struct
            .protected
            .generate_aad()
            .context("unable to generate AAD")?;

        Ok(AttestationResponse {
            success: true,
            secret: Some(resp_struct.ciphertext),
            decryption: Some(AesGcmData {
                epk,
                wrapped_cek: resp_struct.encrypted_key,
                aad,
                iv: resp_struct.iv,
                tag: resp_struct.tag,
            }),
        })
    }

    fn resource(
        &mut self,
        http: &mut HttpClient,
        request: ResourceRequest,
    ) -> anyhow::Result<ResourceResponse> {

        let token = match &request.token {
            AttestationToken::Jwt(jwt) if !jwt.is_empty() => {
                set_attestation_token(jwt.clone());
                jwt.clone()
            }
            AttestationToken::Cwt(cwt) if !cwt.is_empty() => {
                set_attestation_token(cwt.clone());
                cwt.clone()
            }
            _ => get_attestation_token().ok_or_else(|| anyhow!("attestation token not available"))?,
        };

        let request_body = serde_json::to_vec(&request)
            .context("serialize resource request")?;

        let http_resp = http
            .cli
            .put(format!("{}/kbs/v0/resource/lawson/secret/cvm0", http.url))
            .header("Content-Type", "application/json")
            .bearer_auth(&token)
            .body(request_body)
            .send()
            .context("unable to PUT to KBS /resource endpoint")?;

        if http_resp.status() != StatusCode::OK {
            return Ok(ResourceResponse {
                success: false,
                secret: None,
                decryption: None,
            });
        }

        let body_bytes = http_resp
            .bytes()
            .context("unable to read KBS /resource response")?;

        // Debug print raw response bytes (debug and hex) for investigation
        let bb = body_bytes.clone();
        println!("[aproxy-protocol] resp bytes of /resource (len={}): \n{:?}", bb.len(), &bb);
        println!(
            "[aproxy-protocol] resp bytes of /resource (hex): \n{}",
            bb.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
        );

        let resp_struct: Response = serde_json::from_slice(&body_bytes)
            .context("unable to deserialize KBS /resource response")?;
        println!("[aproxy-protocol] resp body of /resource is:\n{:?}", &resp_struct);

        let epk = unwrap_epk(&resp_struct)?;
        let aad = resp_struct
            .protected
            .generate_aad()
            .context("unable to generate AAD")?;

        Ok(ResourceResponse {
            success: true,
            secret: Some(resp_struct.ciphertext),
            decryption: Some(AesGcmData {
                epk,
                wrapped_cek: resp_struct.encrypted_key,
                aad,
                iv: resp_struct.iv,
                tag: resp_struct.tag,
            }),
        })

    }
}


fn unwrap_epk(resp: &Response) -> anyhow::Result<EcP256PublicKey> {
    let epk = resp
        .protected
        .other_fields
        .get("epk")
        .context("epk not found")?;

    let _crv = epk
        .get("crv")
        .context("EC crv value not found")?
        .as_str()
        .context("unable to convert EC crv value to string")?;

    let mut x = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("x")
                .context("EC x value not found")?
                .as_str()
                .context("unable to convert EC x value to string")?,
        )
        .context("unable to decode EC x value from base64")?;

    let mut y = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("y")
                .context("EC y value not found")?
                .as_str()
                .context("unable to convert EC y value to string")?,
        )
        .context("unable to decode EC y value from base64")?;

    let expected_len = match _crv {
        "P-521" => 66,
        "P-256" => 32,
        "P-384" => 48,
        _ => x.len().max(y.len()),
    };

    if x.len() == expected_len + 1 && x[0] == 0 {
        println!("[aproxy-protocol] normalized EC x by stripping leading zero, len {} -> {}", x.len(), expected_len);
        x.remove(0);
    }
    if y.len() == expected_len + 1 && y[0] == 0 {
        println!("[aproxy-protocol] normalized EC y by stripping leading zero, len {} -> {}", y.len(), expected_len);
        y.remove(0);
    }

    if x.len() != expected_len || y.len() != expected_len {
        return Err(anyhow!(
            "invalid EC coordinate length: x={} y={} expected={} for curve {}",
            x.len(),
            y.len(),
            expected_len,
            _crv
        ));
    }

    Ok(EcP256PublicKey { x, y })
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    pub token: String,
}
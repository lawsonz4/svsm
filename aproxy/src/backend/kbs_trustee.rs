// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::Context;
use kbs15::*;
use reqwest::StatusCode;
use serde_json::Value;
use libaproxy::*;
use base64::{
    prelude::{BASE64_URL_SAFE_NO_PAD},
    Engine,
};

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
        println!("[aproxy-protocol] req of /atuth is {}", serde_json::to_string(&req).unwrap());

        // Fetch challenge containing a nonce from the KBS /auth endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/auth", http.url))
            .json(&req)
            .send()
            .context("unable to POST to KBS /auth endpoint")?;

        let text = http_resp
            .text()
            .context("unable to convert KBS /auth response to text")?;
        println!("[aproxy-protocol] resp of /auth is {}", text);

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
        // let bytes: Vec<u8> = vec![72, 101, 108, 108, 111]; // "Hello"
        // let fake_evidence = Value::Array(
        //     bytes.into_iter().map(|b| Value::Number(b.into())).collect()
        // );

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

        println!("[aproxy-protocol] req struct of /attest is {:?}", &attestation);
        let attestation_bytes = serde_json::to_vec(&attestation).context("serialize attestation")?;
        println!("[aproxy-protocol] req bytes of /attest is {:?}", &attestation_bytes);

        // Attest TEE evidence at KBS /attest endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/attest", http.url))
            .header("Content-Type", "application/json")
            .body(attestation_bytes)
            // .json(&attestation)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;
        // println!("[aproxy-protocol] resp of /attest header is {:?}", http_resp);


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

        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
            });
        }

        // let jwe = http_resp.bytes().unwrap();
        // println!("[aproxy-protocol] resp bytes of /attest body is {:?}", &jwe);


        let http_resp = http
            .cli
            .get(format!("{}/kbs/v0/resource/lawson/secret/cvm0", http.url))
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        println!("[aproxy-protocol] lawson/secret/cvm0 resp header is {:?}", &http_resp);
        // println!("[aproxy-protocol] lawson/secret/cvm0 resp header is {:?}", &http_resp.text());

        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
            });
        }

        //读body
        let body_bytes = http_resp
            .bytes()
            .context("unable to read KBS /resource response")?;
        // 反序列化
        let resp: Response = serde_json::from_slice(&body_bytes).unwrap();
        println!("[svsm driver] attestation resp is {:?}", &resp);

        let epk = unwrap_epk(&resp)?;
        let aad = resp
            .protected
            .generate_aad()
            .context("unable to generate AAD")?;

        Ok(AttestationResponse {
            success: true,
            secret: Some(resp.ciphertext),
            decryption: Some(AesGcmData {
                epk,
                wrapped_cek: resp.encrypted_key,
                aad,
                iv: resp.iv,
                tag: resp.tag,
            }),
        })

        // let http_resp = http
        //     .cli
        //     .post(format!("{}/kbs/v0/svsm_secret", http.url))
        //     .send()
        //     .context("unable to POST to KBS /attest endpoint")?;
        // println!("[aproxy-protocol] /svsm_secret resp is {:?}", &http_resp);


        // Successful attestation. Fetch the secret (which should be stored as "svsm_secret" within
        // the KBS's RVPS.
        // let http_resp = http
        //     .cli
        //     .post(format!("{}/kbs/v0/svsm_secret", http.url))
        //     .send()
        //     .context("unable to POST to KBS /attest endpoint")?;
        // println!("[aproxy-protocol] /svsm_secret resp is {:?}", &http_resp);

        // Unsuccessful attempt at retrieving secret.
        // if http_resp.status() != StatusCode::OK {
        //     return Ok(AttestationResponse {
        //         success: false,
        //         secret: None,
        //         pub_key: None,
        //     });
        // }

        // let text = http_resp
        //     .text()
        //     .context("unable to read KBS /resource response")?;
        // println!("[aproxy-protocol] lawson/secret/cvm0 resp text is {:?}", &text);


        // let resp: Response = serde_json::from_str(&text)
        //     .context("unable to convert KBS /resource response to KBS Response object")?;
        // println!("[aproxy-protocol] lawson/secret/cvm0 resp structure is {:?}", &resp);


        // let pub_key = {

        //     let val = serde_json::from_slice(&resp.encrypted_key).unwrap();
        //     let Value::Object(map) = val else {
        //         panic!();
        //     };

        //     let x = map.get("x_b64url").unwrap();
        //     let Value::String(x) = x else {
        //         panic!();
        //     };

        //     let y = map.get("y_b64url").unwrap();
        //     let Value::String(y) = y else {
        //         panic!();
        //     };

        //     AttestationKey::EC {
        //         crv: "EC521".to_string(),
        //         x_b64url: x.to_string(),
        //         y_b64url: y.to_string(),
        //     }
        // };

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

    let x = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("x")
                .context("EC x value not found")?
                .as_str()
                .context("unable to convert EC x value to string")?,
        )
        .context("unable to decode EC x value from base64")?;

    let y = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("y")
                .context("EC y value not found")?
                .as_str()
                .context("unable to convert EC y value to string")?,
        )
        .context("unable to decode EC y value from base64")?;

    Ok(EcP256PublicKey { x, y })
}

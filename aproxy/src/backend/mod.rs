// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod kbs_trustee;

use anyhow::{anyhow, Context};
use kbs_trustee::TrusteeProtocol;
use libaproxy::*;
use reqwest::{blocking::Client, cookie::Jar};
use std::{str::FromStr, sync::Arc};

/// HTTP client and protocol identifier.
#[derive(Clone, Debug)]
pub struct HttpClient {
    pub cli: Client,
    pub url: String,
    protocol: Protocol,
}

impl HttpClient {
    pub fn new(url: String, _: Protocol) -> anyhow::Result<Self> {
        let cli = Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .build()
            .context("unable to build HTTP client to interact with attestation server")?;

        Ok(Self { cli, url, protocol: Protocol::Empty })
    }

    pub fn negotiation(&mut self, req: NegotiationRequest) -> anyhow::Result<NegotiationResponse> {
        // Depending on the underlying protocol of the attestation server, gather negotiation
        // parameters accordingly.
        match req.version.as_str() {
            "0.4.0" => {
                self.protocol = Protocol::Trustee(TrusteeProtocol);
            }
            _ => {}
        }

        match self.protocol {
            Protocol::Trustee(mut trustee) => trustee.negotiation(self, req),
            Protocol::Empty => return Err(anyhow!("protocol not initialized")),
        }
    }

    pub fn attestation(&mut self, req: AttestationRequest) -> anyhow::Result<AttestationResponse> {
        match self.protocol {
            Protocol::Trustee(mut trustee) => trustee.attestation(self, req),
            Protocol::Empty => return Err(anyhow!("protocol not initialized")),
        }
    }
}

/// Attestation Protocol identifier.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Empty,
    Trustee(TrusteeProtocol),
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.to_lowercase()[..] {
            "trustee" => Ok(Self::Trustee(TrusteeProtocol)),
            _ => Err(anyhow!("invalid backend attestation protocol selected")),
        }
    }
}

/// Trait to implement the negotiation and attestation phases across different attestation
/// protocols.
pub trait AttestationProtocol {
    fn negotiation(
        &mut self,
        client: &mut HttpClient,
        req: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse>;
    fn attestation(
        &mut self,
        client: &mut HttpClient,
        req: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse>;
}

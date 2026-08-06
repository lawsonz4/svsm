// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod attest;
mod backend;

use anyhow::Context;
use clap::Parser;
use std::{fs, os::unix::net::UnixListener};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    /// Supported servers include:
    /// kbs-test: https://github.com/tylerfanelli/kbs-test (for testing).
    #[clap(long = "protocol")]
    backend: backend::Protocol,

    /// UNIX domain socket path to the SVSM serial port
    #[clap(long)]
    unix: String,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.force {
        let _ = fs::remove_file(args.unix.clone());
    }

    let listener = UnixListener::bind(args.unix).context("unable to bind to UNIX socket")?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut http_client = backend::HttpClient::new(args.url.clone(), args.backend)?;
                println!("[aproxy-server] http client info is:\n{:#?}", &http_client);

                // Keep reading generic payloads and dispatch by trying to deserialize
                // into known request types. The first successful deserialization
                // determines the handler. `stream` is used only to write responses
                // via `attest::proxy_write`.
                loop {
                    let payload = match attest::proxy_read(&mut stream) {
                        Ok(p) => p,
                        Err(e) => {
                            println!("[aproxy-server] session end or read error: {:?}", e);
                            break;
                        }
                    };
                    // Resource?
                    if let Ok(req) = serde_json::from_slice::<libaproxy::ResourceRequest>(&payload) {
                        println!("[aproxy-server] ResourceRequest struct from svsm is:\n{:?}", &req);
                        let response = http_client.resource(req)?;
                        println!("[aproxy-server] ResourceResponse struct from protocol is:\n{:?}", &response);
                        attest::proxy_write(&mut stream, response)?;
                        continue;
                    }

                    // Negotiation?
                    if serde_json::from_slice::<libaproxy::NegotiationRequest>(&payload).is_ok() {
                        attest::negotiation_with_payload(payload, &mut stream, &mut http_client)?;
                        continue;
                    }

                    // Attestation?
                    if serde_json::from_slice::<libaproxy::AttestationRequest>(&payload).is_ok() {
                        attest::attestation_with_payload(payload, &mut stream, &mut http_client)?;
                        continue;
                    }



                    println!("[aproxy-server] Unknown request payload received: {:?}", &payload);
                }
            }
            Err(_) => {
                panic!("error");
            }
        }
    }

    Ok(())
}

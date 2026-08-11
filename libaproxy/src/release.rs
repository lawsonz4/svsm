// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// The release request payload sent to the proxy from SVSM.
/// Used to notify the KBS that resources can be released/cleaned up.
#[derive(Serialize, Deserialize, Debug)]
pub struct ReleaseRequest {
    /// Mock field — placeholder for future extensions.
    pub mock: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReleaseResponse {
    /// Whether the release operation succeeded.
    pub success: bool,
}

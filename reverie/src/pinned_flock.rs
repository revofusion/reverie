/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::reserved_input::InputDescriptorFacts;

/// An owned native duplicate of a guest's exact open-file description.
///
/// Unlike reopening a procfs path, this retains Linux flock ownership even if
/// the guest closes or reuses its descriptor number. Dropping the pin closes
/// only this reference; it does not explicitly unlock aliases of the OFD.
/// Capture facts are immutable observations, not refreshed state after waiting.
/// This is native backend state and must not be serialized or reconstructed
/// from a descriptor number. Use [`crate::Guest::pin_flock`] to obtain a pin and
/// [`crate::Guest::flock_pinned`] to execute a nonblocking guest-owned probe.
#[derive(Debug)]
pub struct PinnedFlock {
    facts: InputDescriptorFacts,
    pin: OwnedFd,
}

impl PinnedFlock {
    /// Backend constructor after verifying exact native description custody.
    ///
    /// `pin` must be a duplicate of the stopped guest's OFD, not a reopen, and
    /// `facts` must have been captured from that same OFD at the owned stop.
    pub fn from_native_parts(facts: InputDescriptorFacts, pin: OwnedFd) -> Self {
        Self { facts, pin }
    }

    /// Observations at capture, which remain unchanged across subsequent waits.
    pub fn facts(&self) -> &InputDescriptorFacts {
        &self.facts
    }
}

impl AsFd for PinnedFlock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.pin.as_fd()
    }
}

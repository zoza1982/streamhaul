//! [`Capabilities`] — the set of actions a remote peer may perform.
//!
//! This is a `bitflags` `u32`. Each bit corresponds to one channel-level privilege.
//! The intersection of multiple sources (device ACL, UGC, attended selection, account
//! policy) forms the sealed mask — most-restrictive wins.

use bitflags::bitflags;

bitflags! {
    /// The set of actions a remote peer is authorised to perform in a Streamhaul session.
    ///
    /// Each bit gates a distinct privilege. The sealed mask in [`crate::authz::SessionAuthorizer`]
    /// is the **bitwise AND** of four independent sources; any source can only *remove* bits.
    ///
    /// # Encoding
    ///
    /// The full `u32` is encoded big-endian in a UGC `CAPS` field. Unknown bits are dropped by
    /// [`Capabilities::from_bits_truncate`] on decode (an attacker setting reserved bits gains
    /// nothing).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::Capabilities;
    ///
    /// let viewer = Capabilities::VIEW;
    /// let controller = Capabilities::VIEW | Capabilities::CONTROL;
    /// // Intersection keeps only the view bit:
    /// assert_eq!(viewer & controller, Capabilities::VIEW);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u32 {
        /// Observe the screen (Video channel) — the baseline grant.
        const VIEW      = 1 << 0;
        /// Pointer + keyboard injection (Input channel).
        const CONTROL   = 1 << 1;
        /// Read/write the host clipboard (Clipboard channel).
        const CLIPBOARD = 1 << 2;
        /// Start/receive file transfers (File channel).
        const FILE      = 1 << 3;
        /// Receive host audio (Audio channel).
        const AUDIO     = 1 << 4;
        /// Perform admin/UAC-class actions — requires **fresh presence** in addition to this bit.
        ///
        /// The sealed mask may carry this bit, but [`SessionAuthorizer::authorize`] for any
        /// elevation action also requires a [`FreshPresence`](crate::authz::FreshPresence) proof
        /// within the freshness window. Without it, the action is denied even when this bit is set.
        const ELEVATION = 1 << 5;
    }
}

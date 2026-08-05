//! Display summary handed to the UI for user confirmation.
//!
//! Everything in here has been verified against the PCZT's cryptographic
//! commitments and the device's own keys before it is shown to the user.

use serde::Serialize;

/// Which value pool an item belongs to.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    Transparent,
    Orchard,
    Ironwood,
}

/// A spend the device will sign (always owned by this wallet).
#[derive(Clone, Debug, Serialize)]
pub struct SpendSummary {
    pub pool: Pool,
    /// Value in zatoshis.
    pub value: u64,
}

/// An output of the transaction.
#[derive(Clone, Debug, Serialize)]
pub struct OutputSummary {
    pub pool: Pool,
    /// The user-facing address (verified to contain the raw recipient).
    pub address: String,
    /// Value in zatoshis.
    pub value: u64,
    /// True when this output returns funds to this wallet (verified change).
    pub is_change: bool,
}

/// The verified transaction summary shown on the confirmation screen.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    /// "main" or "test".
    pub network: String,
    /// Spends this device will sign.
    pub spends: Vec<SpendSummary>,
    /// All transaction outputs (change flagged).
    pub outputs: Vec<OutputSummary>,
    /// Total zatoshis leaving the wallet to external recipients.
    pub total_out: u64,
    /// Total change zatoshis returning to the wallet.
    pub total_change: u64,
    /// Transaction fee in zatoshis.
    pub fee: u64,
    /// Transaction expiry height (0 = none).
    pub expiry_height: u32,
}

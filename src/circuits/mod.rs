use serde::{Deserialize, Serialize};

/// Identifier for GroveSTARK circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitId {
    /// Circuit 1 — Dash Platform contract membership / document ownership.
    ContractMembership,
    // Future circuits (e.g., Masternode ownership) will be introduced here.
}

impl CircuitId {
    /// Human-readable name for logging and UX.
    pub fn label(&self) -> &'static str {
        match self {
            CircuitId::ContractMembership => "Contract Membership",
        }
    }
}

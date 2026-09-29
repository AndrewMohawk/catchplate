//! Purpose-fixed durable canary delivery. No generic RPC or caller verdict.
mod wire;
mod configuration;
mod radix;
mod completion;
pub use configuration::{Configuration, CanaryBinding, RecoveryTarget, Authority};
pub use completion::{Completion, Observation};
pub use wire::{Operation, Prepared, Signed, Selector, Sender, MAX_RESPONSE, PATH};
pub(crate) use wire::{ascii, document, exact, framed, text, number, require};

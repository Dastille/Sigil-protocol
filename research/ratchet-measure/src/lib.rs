//! Ratchet / damage-marking repair measurement harness for Sigil Seal (8-of-16).
//! Research only: no `.sg1` format change, no change to the sigil crate.
#![forbid(unsafe_code)]

pub mod decoders;
pub mod gf;
pub mod harness;
pub mod rs;
pub mod sidecar;

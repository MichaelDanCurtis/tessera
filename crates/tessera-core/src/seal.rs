use std::sync::atomic::{AtomicBool, Ordering};

use crate::types::TesseraError;

/// V1 seal model: a single master key unseals; sealed refuses all KV ops.
/// Multi-key (Shamir) ceremony is deferred.
pub struct SealState {
    sealed: AtomicBool,
    master_key: Vec<u8>,
}

impl SealState {
    /// Construct sealed, holding the configured master key.
    pub fn new(master_key: Vec<u8>) -> Self {
        Self { sealed: AtomicBool::new(true), master_key }
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::SeqCst)
    }

    /// Unseal iff the presented key matches the configured master key.
    pub fn unseal(&self, key: &[u8]) -> Result<(), TesseraError> {
        if key == self.master_key.as_slice() {
            self.sealed.store(false, Ordering::SeqCst);
            Ok(())
        } else {
            Err(TesseraError::InvalidToken)
        }
    }

    pub fn seal(&self) {
        self.sealed.store(true, Ordering::SeqCst);
    }

    /// Guard helper: `Err(Sealed)` when sealed, else `Ok(())`.
    pub fn require_unsealed(&self) -> Result<(), TesseraError> {
        if self.is_sealed() { Err(TesseraError::Sealed) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_sealed() {
        let s = SealState::new(b"master".to_vec());
        assert!(s.is_sealed());
        assert_eq!(s.require_unsealed(), Err(TesseraError::Sealed));
    }

    #[test]
    fn correct_key_unseals_wrong_key_rejected() {
        let s = SealState::new(b"master".to_vec());
        assert_eq!(s.unseal(b"wrong"), Err(TesseraError::InvalidToken));
        assert!(s.is_sealed());
        s.unseal(b"master").unwrap();
        assert!(!s.is_sealed());
        s.require_unsealed().unwrap();
    }

    #[test]
    fn seal_again_blocks_ops() {
        let s = SealState::new(b"m".to_vec());
        s.unseal(b"m").unwrap();
        s.seal();
        assert_eq!(s.require_unsealed(), Err(TesseraError::Sealed));
    }
}

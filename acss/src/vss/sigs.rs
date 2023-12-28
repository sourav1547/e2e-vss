use aptos_bitvec::BitVec;
use aptos_crypto::{bls12381::{self, PublicKey}, Signature};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Deserialize, Serialize};

use aptos_crypto::ed25519::Ed25519PublicKey;
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};


/// Modification to make things simple

/// This struct represents a BLS multi-signature or aggregated signature:
/// it stores a bit mask representing the set of validators participating in the signing process
/// and the multi-signature/aggregated signature itself,
/// which was aggregated from these validators' partial BLS signatures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash, Default)]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    sig: Option<bls12381::Signature>,
}

impl AggregateSignature {
    pub fn new(
        validator_bitmask: BitVec,
        aggregated_signature: Option<bls12381::Signature>,
    ) -> Self {
        Self {
            validator_bitmask,
            sig: aggregated_signature,
        }
    }

    pub fn empty() -> Self {
        Self {
            validator_bitmask: BitVec::default(),
            sig: None,
        }
    }

    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }

    pub fn get_signers_addresses(
        &self,
        validator_addresses: &[PublicKey],
    ) -> Vec<PublicKey> {
        validator_addresses
            .iter()
            .enumerate()
            .filter_map(|(index, addr)| {
                let addr_copy = addr.clone();
                if self.validator_bitmask.is_set(index as u16) {
                    Some(addr_copy)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_num_voters(&self) -> usize {
        self.validator_bitmask.count_ones() as usize
    }

    pub fn sig(&self) -> &Option<bls12381::Signature> {
        &self.sig
    }

    pub fn verify(&self, msg: &[u8], pks: &Vec<&PublicKey>) -> bool {
        let mut aggpks = vec![];
        let n = pks.len();
        for pos in 0..n {
            if self.validator_bitmask.is_set(pos as u16) {
                aggpks.push(pks[pos])
            }
        }
        // for it in self.validator_bitmask.iter_ones() {
        //     aggpks.push(&pks[it]);
        // }

        let aggpk = PublicKey::aggregate(aggpks).unwrap();

        let sig = self.sig.clone().unwrap();
        let valid = sig.verify_arbitrary_msg(&msg, &aggpk).is_ok();
        valid
    }
}




/// Modification to make things simple

/// This struct represents a BLS multi-signature or aggregated signature:
/// it stores a bit mask representing the set of validators participating in the signing process
/// and the multi-signature/aggregated signature itself,
/// which was aggregated from these validators' partial BLS signatures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash, Default)]
pub struct EdSignature {
    validator_bitmask: BitVec,
    sig: Option<MultiEd25519Signature>,
}

impl EdSignature {
    pub fn new(
        validator_bitmask: BitVec,
        ed_signature: Option<MultiEd25519Signature>,
    ) -> Self {
        Self {
            validator_bitmask,
            sig: ed_signature,
        }
    }

    pub fn empty() -> Self {
        Self {
            validator_bitmask: BitVec::default(),
            sig: None,
        }
    }

    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }

    pub fn get_signers_addresses(
        &self,
        validator_addresses: &[Ed25519PublicKey],
    ) -> Vec<Ed25519PublicKey> {
        validator_addresses
            .iter()
            .enumerate()
            .filter_map(|(index, addr)| {
                let addr_copy = addr.clone();
                if self.validator_bitmask.is_set(index as u16) {
                    Some(addr_copy)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_num_voters(&self) -> usize {
        self.validator_bitmask.count_ones() as usize
    }

    pub fn sig(&self) -> &Option<MultiEd25519Signature> {
        &self.sig
    }

    pub fn verify(&self, msg: &[u8], pk: &MultiEd25519PublicKey) -> bool {
        let sig = self.sig.clone().unwrap();
        let valid = sig.verify_arbitrary_msg(&msg, &pk).is_ok();
        valid
    }
}
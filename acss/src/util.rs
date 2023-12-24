use blstrs::{G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use crate::{G1_PROJ_NUM_BYTES, G2_PROJ_NUM_BYTES, SCALAR_NUM_BYTES};

/// Helper type for efficient serialization of a `Vec<[u8; G1_PROJ_NUM_BYTES]>`, which `serde_bytes`
/// foolishly can't handle.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct G1Slice {
    #[serde_as(as = "Bytes")]
    pub(crate) inner: [u8; G1_PROJ_NUM_BYTES]
}

impl From<[u8; G1_PROJ_NUM_BYTES]> for G1Slice  {
    fn from(inner: [u8; G1_PROJ_NUM_BYTES]) -> Self {
        G1Slice {
            inner
        }
    }
}

/// Helper type for efficient serialization of a `Vec<[u8; G2_PROJ_NUM_BYTES]>`, which `serde_bytes`
/// foolishly can't handle.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct G2Slice {
    #[serde_as(as = "Bytes")]
    pub(crate) inner: [u8; G2_PROJ_NUM_BYTES]
}

impl From<[u8; G2_PROJ_NUM_BYTES]> for G2Slice {
    fn from(inner: [u8; G2_PROJ_NUM_BYTES]) -> Self {
        G2Slice {
            inner
        }
    }
}

/// Helper type for efficient serialization of a `Vec<[u8; SCALAR_NUM_BYTES]>`, which `serde_bytes`
/// foolishly can't handle.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ScalarSlice {
    #[serde_as(as = "Bytes")]
    pub(crate) inner: [u8; SCALAR_NUM_BYTES]
}

impl From<[u8; SCALAR_NUM_BYTES]> for ScalarSlice {
    fn from(inner: [u8; SCALAR_NUM_BYTES]) -> Self {
        ScalarSlice {
            inner
        }
    }
}

pub(crate) fn append_scalar(t: &mut merlin::Transcript, label: &'static [u8], p: &Scalar) {
    t.append_message(label, p.to_bytes_be().as_slice())
}

pub(crate) fn append_scalars(t: &mut merlin::Transcript, label: &'static [u8], vec: &Vec<Scalar>) {
    t.append_u64(label, vec.len() as u64);
    for p in vec {
        t.append_message(label, p.to_bytes_be().as_slice())
    }
}


pub(crate) fn append_g1_point(t: &mut merlin::Transcript, label: &'static [u8], p: &G1Projective) {
    t.append_message(label, p.to_compressed().as_slice())
}

pub(crate) fn append_g1_vector(t: &mut merlin::Transcript, label: &'static [u8], vec: &Vec<G1Projective>) {
    t.append_u64(label, vec.len() as u64);
    for p in vec {
        t.append_message(b"g1_point", p.to_compressed().as_slice())
    }
}
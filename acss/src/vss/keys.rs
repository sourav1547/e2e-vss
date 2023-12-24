use crate::{G1_PROJ_NUM_BYTES, SCALAR_NUM_BYTES, random_scalar, random_scalars};
use crate::vss::public_parameters::PublicParameters;

use aptos_crypto_derive::{SilentDebug, SilentDisplay};
use blstrs::{G1Projective, Scalar};
use more_asserts::{assert_ge, assert_le};
use std::ops::{Mul, AddAssign};
use ff::Field;
use crate::lagrange::lagrange_coefficients_at_zero;
use crate::polynomials::poly_eval;
use crate::pvss::{Player, SharingConfiguration};

/// The size of a serialized *dealt secret key*.
const DEALT_SK_NUM_BYTES : usize = SCALAR_NUM_BYTES;

/// The size of a serialized *dealt secret key share*.
const DEALT_SK_SHARE_NUM_BYTES : usize = SCALAR_NUM_BYTES;

/// The size of a serialized *dealt public key*.
const DEALT_PK_NUM_BYTES : usize = G1_PROJ_NUM_BYTES;


#[derive(SilentDebug, SilentDisplay, PartialEq, Clone)]
pub struct InputSecret {
    inner: InputSecretInner
}

#[derive(PartialEq, Clone)]
struct InputSecretInner {
    /// The actual secret being dealt; 
    a: Scalar,
    /// 
    pub(crate) f: Vec<Scalar>,
    pub(crate) r: Vec<Scalar>, 
}

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(InputSecret: Clone);

/// The *dealt secret key* that will be output by the PVSS reconstruction algorithm. This will be of
/// a different type than the *input secret* that was given as input to PVSS dealing.
///
/// This secret key will never be reconstructed in plaintext. Instead, we will use a simple/efficient
/// multiparty computation protocol to reconstruct a function of this secret (e.g., a verifiable
/// random function evaluated on an input `x` under this secret).
///
/// NOTE: We do not implement (de)serialization for this because a dealt secret key `sk` will never be
/// materialized in our protocol. Instead, we always use some form of efficient multi-party computation
/// MPC protocol to materialize a function of `sk`, such as `f(sk, m)` where `f` is a verifiable random
/// function (VRF), for example.
#[derive(SilentDebug, SilentDisplay, PartialEq)]
pub struct DealtSecretKey {
    /// A group element $\hat{h}_1^a \in G_2$
    pub(crate) a: Scalar,
}

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(DealtSecretKey: Clone);

#[derive(SilentDebug, SilentDisplay)]
pub struct DealtSecretKeyShare(pub(crate) DealtSecretKey);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(DealtSecretKeyShare: Clone);

/// The *dealt public key* associated with the the secret key that was dealt via the PVSS transcript.
#[derive(Clone)]
pub struct DealtPublicKey {
    /// A group element $g_1^a \in G_1$
    pub(crate) g1_a: G1Projective,
}

/// A player's *share* of the *dealt public key* from above.
#[derive(Clone)]
pub struct DealtPublicKeyShare(pub(crate) DealtPublicKey);

//
// InputSecret implementation
//
impl InputSecret {
    pub fn new_random<R>(sc: &SharingConfiguration, pedersen: bool, rng: &mut R) -> Self
        where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
    {
        let a = random_scalar(rng);
        let mut f = random_scalars(sc.t, rng);
        
        // Decides to add randomness depending upon the value of the pedersen flag
        let mut r = random_scalars(sc.t, rng);
        if !pedersen {
            for i in 0..sc.t {
                r[i] = Scalar::zero();
            }
        }

        f[0] = a;

        debug_assert!(f.len() == sc.t);
        debug_assert_eq!(poly_eval(&f, &Scalar::zero()), a);

        InputSecret {
            inner: InputSecretInner {
                a,
                f,
                r,
            }
        }
    }

    pub fn get_secret_a(&self) -> Scalar {
        self.inner.a.clone()
    }

    pub fn get_secret_f(&self) -> &Vec<Scalar> {
        &self.inner.f
    }

    pub fn get_secret_r0(&self) -> Scalar {
        self.inner.r[0]
    }

    pub fn get_secret_r(&self) -> &Vec<Scalar> {
        &self.inner.r
    }
    
    pub fn to_dealt_secret_key(&self) -> DealtSecretKey {
        DealtSecretKey {
            a: self.get_secret_a()
        }
    }
}


pub fn inner_prod(a :Vec<Scalar>, b :Vec<Scalar>) -> Scalar {
    let mut ip = Scalar::zero();
    for i in 0..b.len() {
        ip.add_assign(b[i].mul(a[i]));
    }
    ip
}

//
// DealtSecretKey implementation & traits
//
impl DealtSecretKey {
    /// Serializes the dealt secret key.
    pub fn to_bytes(&self) -> [u8; DEALT_SK_NUM_BYTES] {
        self.a.to_bytes_le()
    }

    /// Reconstructs the `DealtSecretKey` given a sufficiently-large subset of shares from players.
    /// Mainly used for testing the PVSS transcript dealing and decryption.
    pub fn reconstruct(sc: &SharingConfiguration, shares: &Vec<(Player, DealtSecretKeyShare)>) -> Self {
        assert_ge!(shares.len(), sc.get_threshold());
        assert_le!(shares.len(), sc.get_total_num_players());

        let ids = shares.iter().map(|(p, _)| p.id).collect::<Vec<usize>>();
        let lagr = lagrange_coefficients_at_zero(sc.get_batch_evaluation_domain(), ids.as_slice());
        let bases = shares.iter().map(|(_, share)| share.0.a).collect::<Vec<Scalar>>();

        assert_eq!(lagr.len(), bases.len());

        DealtSecretKey{
            a:inner_prod(bases, lagr)
        }
    }
}

//
// DealtSecretKeyShare implementation & traits
//

impl DealtSecretKeyShare {
    /// Serializes the dealt secret key share.
    pub fn to_bytes(&self) -> [u8; DEALT_SK_SHARE_NUM_BYTES] {
        self.0.to_bytes()
    }
}

//
// DealtPublicKey[Share]
//
impl DealtPublicKey {

    /// Serializes a dealt public key.
    pub fn to_bytes(&self) -> [u8; DEALT_PK_NUM_BYTES] {
        self.g1_a.to_compressed()
    }

    /// Computes the public key associated with the given input secret.
    /// NOTE: In this construction, a `DealtPublicKey` cannot be computed from a `DealtSecretKey` directly.
    pub fn from_secret_key(sk: &InputSecret, pp: &PublicParameters) -> DealtPublicKey {
        let s = sk.get_secret_a();
        let r = sk.get_secret_r0();
        
        let g = pp.get_commitment_base();
        let h = pp.get_randomness_base();

        DealtPublicKey {
            g1_a: G1Projective::multi_exp([g,h].as_slice(), [s,r].as_slice())
        }
    }
}

impl DealtPublicKeyShare {
    /// Serializes a dealt public key share.
    pub fn to_bytes(&self) -> [u8; DEALT_PK_NUM_BYTES] {
        self.0.to_bytes()
    }
}
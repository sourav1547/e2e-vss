use crate::{DST_PVSS_PUBLIC_PARAMS_GENERATION, G1_PROJ_NUM_BYTES, SEED_PVSS_PUBLIC_PARAMS_GENERATION};
use blstrs::G1Projective;
use aptos_crypto::{CryptoMaterialError, ValidCryptoMaterial, ValidCryptoMaterialStringExt};
use aptos_crypto_derive::{DeserializeKey, SerializeKey};
use group::Group;

/// The size, in number of bytes, of a serialized `PublicParameters` struct.
const NUM_BYTES : usize = 2*G1_PROJ_NUM_BYTES;

#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct PublicParameters {
    /// Pedersen polynomial commitment parameters
    bases: [G1Projective; 2]
}

impl PublicParameters {
    pub fn new_from_seed(seed: &[u8]) -> Self {
        // let g = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"g1");
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        
        PublicParameters { 
            bases: [g, h],
        }
    }

    pub fn default() -> Self {
        Self::new_from_seed(SEED_PVSS_PUBLIC_PARAMS_GENERATION)
    }

    pub fn get_commitment_base(&self) -> G1Projective {
        self.bases[0]
    }

    pub fn get_randomness_base(&self) -> G1Projective {
        self.bases[1]
    }

    pub fn get_bases(&self) -> &[G1Projective] {
        self.bases.as_slice()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bases[0].to_compressed().to_vec();
        bytes.append(&mut self.bases[1].to_compressed().to_vec());

        bytes
    }
}

impl ValidCryptoMaterial for PublicParameters {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl TryFrom<&[u8]> for PublicParameters {
    type Error = CryptoMaterialError;

    /// Deserialize a `PublicParameters` struct
    fn try_from(bytes: &[u8]) -> std::result::Result<PublicParameters, Self::Error> {
        let slice : &[u8; NUM_BYTES] = match <&[u8; NUM_BYTES]>::try_from(bytes) {
            Ok(slice) => slice,
            Err(_) => return Err(CryptoMaterialError::WrongLengthError),
        };

        let g1_bytes = slice[0..G1_PROJ_NUM_BYTES].try_into().unwrap();
        let h1_bytes = slice[G1_PROJ_NUM_BYTES..2*G1_PROJ_NUM_BYTES].try_into().unwrap();

        let g1_opt = G1Projective::from_compressed(g1_bytes);
        let h1_opt = G1Projective::from_compressed(h1_bytes);
        
        if g1_opt.is_some().unwrap_u8() == 1u8 &&
            h1_opt.is_some().unwrap_u8() == 1u8
        {
            Ok(PublicParameters {
                bases: [g1_opt.unwrap(),h1_opt.unwrap()],
            })
        } else {
            Err(CryptoMaterialError::DeserializationError)
        }
    }
}

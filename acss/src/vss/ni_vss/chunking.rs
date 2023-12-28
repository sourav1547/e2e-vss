use blstrs::Scalar;
use crate::SCALAR_NUM_BYTES;
use zeroize::Zeroize;


/// The size of a chunk in bytes
pub const CHUNK_BYTES: usize = 2;

/// The size of a chunk in bits
pub const CHUNK_BITS: usize = CHUNK_BYTES * 8;

/// The range of a chunk (ie, the cardinality of the set)
pub const CHUNK_SIZE: usize = 1 << CHUNK_BITS;

/// The type of a chunk, which must be able to hold CHUNK_MIN..=CHUNK_MAX
pub type Chunk = isize;

/// The smallest value that a chunk can take
pub const CHUNK_MIN: Chunk = 0;

/// The largest value that a chunk can take
pub const CHUNK_MAX: Chunk = CHUNK_MIN + (CHUNK_SIZE as Chunk) - 1;

/// The ciphertext is an encoded Scalar element
pub(crate) const MESSAGE_BYTES: usize = SCALAR_NUM_BYTES;

/// NUM_CHUNKS is simply the number of chunks needed to hold a message
// pub const NUM_CHUNKS: usize = 24;
pub const NUM_CHUNKS: usize = (MESSAGE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

#[derive(Clone, Debug, Zeroize)]
pub struct PlaintextChunks {
    pub(crate) chunks: [Chunk; NUM_CHUNKS],
}

impl PlaintextChunks {
    /// Create PlaintextChunks by chunking a Scalar value
    pub fn from_scalar(s: &Scalar) -> Self {
        let bytes = s.to_bytes_be();
        let mut chunks = [0; NUM_CHUNKS];

        for i in 0..NUM_CHUNKS {
            let mut buffer = [0u8; CHUNK_BYTES];
            buffer.copy_from_slice(&bytes[CHUNK_BYTES * i..CHUNK_BYTES * (i + 1)]);
            chunks[i] = u16::from_be_bytes(buffer) as isize;
            // chunks[i] = u8::from_be_bytes(buffer) as isize;
        }
        chunks.reverse();

        Self { chunks }
    }

    /// Create a PlaintextChunks by rechunking dlog results
    pub fn from_dlogs(dlogs: &[Scalar]) -> Self {
        let chunk_size = Scalar::from(CHUNK_SIZE as u64);
        let mut acc = Scalar::from(0);
        for dlog in dlogs {
            acc *= &chunk_size;
            acc += dlog;
        }

        Self::from_scalar(&acc)
    }

    /// Return the chunk elements encoded as Scalars
    pub fn chunks_as_scalars(&self) -> [Scalar; NUM_CHUNKS] {
        // TODO: To check whethere c is always positive or not.
        self.chunks.map(|c| Scalar::from(c as u64))
    }

    pub fn recombine_to_scalar(&self) -> Scalar {
        let mut temp_chunk = self.chunks.clone();
        temp_chunk.reverse();
        let factor = Scalar::from(CHUNK_SIZE as u64);

        let mut acc = Scalar::from(0);
        for chunk in temp_chunk {
            acc *= &factor;
            // To check if there is any error due to signed to unsigned transformation
            acc += Scalar::from(chunk as u64);
        }

        acc
    }
}

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::codec::{Codec, Decode, Encode};
use sp_std::vec::Vec;
use sha2::Digest;
use bytes::BufMut;
use sp_core::H256;

const FORKS: &[&[u8]] = &[
    b"0xed91a717313c6eb0e3f082411584d0da8f0c8af2a4ac01e5af1959e0ec4338bc",
    b"0x6d622e615cfd29d0f8cdd9bdd73ca0b769c8661b29d7ba9c45856c96bc2ec5bc",
    b"0x1ce8f721bf0c9fa7473795a97e365ad38bbc539aab821d6912d86f24e67720fc"
];

#[derive(Decode, Encode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PoW {
    pub indices: Vec<u8>,
    pub nonce: Vec<u8>,
    pub difficulty: u32,
}

#[derive(Decode, Encode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BeamBlockHeader {
    pub height: u64,
    pub prev: Vec<u8>,
    pub chain_work: Vec<u8>,
    pub kernels: Vec<u8>,
    pub definition: Vec<u8>,
    pub timestamp: u64,
    pub pow: PoW,
}

fn encode_num(num: u64) -> Vec<u8> {
    let mut buf = Vec::new();

    let mut num = num;
    while num >= 0x80 {
        buf.put_u8((num as u8 | 0x80) as u8);
        num = num >> 7;
    }

    buf.put_u8(num as u8);

    buf
}

fn find_fork(height: u64) -> u8 {
    if height >= 777777 {
        return 2;
    }
    if height >= 321321 {
        return 1;
    }

    0
}

fn get_fork_hash(fork: usize) -> &'static [u8] {
    if fork < FORKS.len() {
        return FORKS[fork];
    }

    FORKS[0]
}


impl PoW {
    pub fn new() -> Self {
        PoW {
            indices: Vec::new(),
            nonce: Vec::new(),
            difficulty: 0,
        }
    }

    /// Creates PoW structure from the given raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut pow = Self::new();
        if bytes.is_empty() {
            pow
        } else {
            let num_solution_bytes = 104;
            let num_nonce_bytes = 8;

            pow.indices.reserve_exact(num_solution_bytes);
            pow.nonce.reserve_exact(num_nonce_bytes);

            pow.indices.extend_from_slice(&bytes[0..num_solution_bytes]);
            pow.nonce.extend_from_slice(&bytes[num_solution_bytes..num_solution_bytes+num_nonce_bytes]);

            let mut difficulty_index = num_solution_bytes + num_nonce_bytes;
            for i in 0..4 {
                let mut temp = bytes[difficulty_index] as u32;
                temp <<= 8 * i;
                pow.difficulty ^= temp;

                difficulty_index += 1;
            }

            pow
        }
    }
}

impl BeamBlockHeader {
    fn encode_state(&self, total: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        // Prefix
        buf.extend(encode_num(self.height));
        buf.extend(self.prev.clone());
        buf.extend(self.chain_work.clone());

        // Element
        buf.extend(self.kernels.iter().cloned());
        buf.extend(self.definition.iter().cloned());
        buf.extend(encode_num(self.timestamp));
        buf.extend(encode_num(self.pow.difficulty.into()));

        let fork = find_fork(self.height);
        if fork >= 2 {
            buf.extend(get_fork_hash(fork.into()));
        }

        if total {
            buf.extend(self.pow.indices.iter().cloned());
            buf.extend(self.pow.nonce.iter().cloned());
        }

        buf
    }

    pub fn get_hash(&self) -> H256 {
        let buf = self.encode_state(true);
        let hash = sha2::Sha256::digest(&buf);

        H256::from_slice(hash.as_slice())
    }
}

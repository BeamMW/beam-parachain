#![cfg_attr(not(feature = "std"), no_std)]

use crate::Error;
use crate::beam_hash_3::{BeamHashIII, BeamPowHelper};
use crate::util::{encode_num, find_fork, get_fork_hash};

use frame_support::debug;
use frame_support::codec::{Codec, Decode, Encode};
use sp_std::{
    vec::Vec,
    convert::TryInto,
};
use sp_core::H256;
use sha2::Digest;


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

#[derive(Decode, Encode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PoW {
    pub indices: Vec<u8>,
    pub nonce: Vec<u8>,
    pub difficulty: u32,
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

    pub fn is_valid(&self, input: &[u8], height: u64) -> bool {
        let state_option = BeamPowHelper::reset(input, &self.nonce, height);

        if let Some(state) = state_option {
            BeamHashIII::is_valid_solution(&state, &self.indices)
        } else {
            false
        }
    }
}

#[test]
fn test_block_header_hash() {
    let height = 903720;
    let prev = vec![0x62, 0x02, 0x0e, 0x8e, 0xe4, 0x08, 0xde, 0x5f, 0xdb, 0xd4, 0xc8, 0x15, 0xe4, 0x7e, 0xa0, 0x98, 0xf5, 0xe3, 0x0b, 0x84, 0xc7, 0x88, 0xbe, 0x56, 0x6a, 0xc9, 0x42, 0x5e, 0x9b, 0x07, 0x80, 0x4d];
    let chain_work = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x0b, 0xd1, 0x5c, 0x0c, 0xf6, 0xe0, 0x00, 0x00];
    let kernels = vec![0xcc, 0xab, 0xdc, 0xee, 0x29, 0xeb, 0x38, 0x84, 0x26, 0x26, 0xad, 0x11, 0x55, 0x01, 0x4e, 0x2d, 0x7f, 0xc1, 0xb0, 0x0d, 0x0a, 0x70, 0xcc, 0xb3, 0x59, 0x08, 0x78, 0xbd, 0xb7, 0xf2, 0x6a, 0x02];
    let definition = vec![0xda, 0x1c, 0xf1, 0xa3, 0x33, 0xd3, 0xe8, 0xb0, 0xd4, 0x4e, 0x4c, 0x0c, 0x16, 0x7d, 0xf7, 0xbf, 0x60, 0x4b, 0x55, 0x35, 0x2e, 0x5b, 0xca, 0x3b, 0xc6, 0x7d, 0xfd, 0x35, 0x0f, 0xb7, 0x07, 0xe9];
    let timestamp = 1600968920;
    let pow_bytes = vec![0x18, 0x83, 0x06, 0x06, 0x8a, 0xf6, 0x92, 0xbd, 0xd9, 0xd4, 0x03, 0x55, 0xee, 0xca, 0x86, 0x40, 0x00, 0x5a, 0xa7, 0xff, 0x65, 0xb6, 0x1a, 0x85, 0xb4, 0x5f, 0xc7, 0x0a, 0x8a, 0x2a, 0xc1, 0x27, 0xdb, 0x2d, 0x90, 0xc4, 0xfc, 0x39, 0x76, 0x43, 0xa5, 0xd9, 0x8f, 0x3e, 0x64, 0x4f, 0x9f, 0x59, 0xfc, 0xf9, 0x67, 0x7a, 0x0d, 0xa2, 0xe9, 0x0f, 0x59, 0x7f, 0x61, 0xa1, 0xbf, 0x17, 0xd6, 0x75, 0x12, 0xc6, 0xd5, 0x7e, 0x68, 0x0d, 0x0a, 0xa2, 0x64, 0x2f, 0x7d, 0x27, 0x5d, 0x27, 0x00, 0x18, 0x8d, 0xbf, 0x8b, 0x43, 0xfa, 0xc5, 0xc8, 0x8f, 0xa0, 0x8f, 0xa2, 0x70, 0xe8, 0xd8, 0xfb, 0xc3, 0x37, 0x77, 0x61, 0x9b, 0x00, 0x00, 0x00, 0x00, 0xad, 0x63, 0x64, 0x76, 0xf7, 0x11, 0x74, 0x00, 0xac, 0xd5, 0x66, 0x18];
    let pow = PoW::from_bytes(&pow_bytes);

    let block_header = BeamBlockHeader {
        height: height,
        prev: prev,
        chain_work: chain_work,
        kernels: kernels,
        definition: definition,
        timestamp: timestamp,
        pow: pow,
    };

    let block_header_hash = block_header.get_hash();
    let expected_block_header_hash = vec![0x23, 0xfe, 0x86, 0x73, 0xdb, 0x74, 0xc4, 0x3d, 0x49, 0x33, 0xb1, 0xf2, 0xd1, 0x6d, 0xb1, 0x1b, 0x1a, 0x48, 0x95, 0xe3, 0x92, 0x4a, 0x2f, 0x9c, 0xaf, 0x92, 0xaf, 0xa8, 0x9f, 0xd0, 0x1f, 0xaf];
    println!("Calculated block header hash: {:X?}", block_header_hash.as_bytes());

    assert_eq!(
        block_header_hash.as_bytes(), expected_block_header_hash
    );
}

use crate::util::{find_fork};

use frame_support::{debug};
use core::ops::{Shl, Shr};

use blake2b_simd::{
    State as Blake2b_State,
    Params as Blake2b_Params,
};
use bitvec::prelude::*;
use bytes::{BufMut};
use fixedbitset::{FixedBitSet};

use sp_std::{
    vec::Vec,
};

const BEAM_HASH_III_WORK_BIT_SIZE: usize = 448;
const BEAM_HASH_III_COLLISION_BIT_SIZE: usize = 24;
const BEAM_HASH_III_NUM_ROUNDS: usize = 5;
const BEAM_HASH_III_SOL_SIZE: usize = 104;


pub struct BeamHashIII;

#[derive(Default, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BeamPowHelper {
    blake_state: Blake2b_State
}

struct BeamHashIII_StepElement {
    work_bits: BitArray<LocalBits, [usize; 1]>,
    //work_bits: bitarr!(for BEAM_HASH_III_WORK_BIT_SIZE, in Lsb0, u8),
    index_tree: Vec<u32>,
}

impl BeamHashIII {
    pub fn initialize_state() -> Blake2b_State {
        let mut personalization: Vec<u8> = Vec::new();
        personalization.put(&b"Beam-PoW"[..]);
        personalization.put_u32_le(BEAM_HASH_III_WORK_BIT_SIZE as u32);
        personalization.put_u32_le(BEAM_HASH_III_NUM_ROUNDS as u32);

        debug::info!("Blake2b personalization: {:x?}", personalization.as_slice());

        Blake2b_Params::new()
            .hash_length(32)
            .fanout(1)
            .max_depth(1)
            .personal(&personalization)
            .to_state()
    }

    pub fn is_valid_solution(base_state: &Blake2b_State , solution: &[u8]) -> bool {
        if solution.len() != 104 {
            return false;
        }

        let mut state = base_state.clone();
        // Last 4 bytes of solution are our extra nonce
        state.update(&solution[100..104]);
        let hash = state.finalize();

        //println!("Blake2b hash: {:?}", &hash.to_hex());
        debug::info!("Blake2b hash: {:?}", &hash.to_hex());

        let mut pre_pow = hash.as_bytes();

        //let mut pre_pow: Vec<u64> = Vec::with_capacity(4);
        //pre_pow.resize(5, 0u64);
        //pre_pow[0] = u32::from_le_bytes(hash.as_bytes().try_into().expect("PoW slice with wrong length")) as u64;

        true
    }
}

impl BeamPowHelper {
    pub fn reset(input: &[u8], nonce: &[u8], height: u64) -> Option<Blake2b_State> {
        // Everything but BeamHashIII is not supported
        if find_fork(height) < 2 {
            return None;
        }

        let mut state = BeamHashIII::initialize_state();
        state.update(input);
        state.update(nonce);

        Some(state)
    }

    pub fn test_difficulty() -> bool {
        //TODO
        true
    }
}

//fn bitset_shl(bitset: FixedBitSet, rhs: usize) -> FixedBitSet {
//    let bits_in_block = 8 * 4;
//    let num_blocks_shift = rhs / bits_in_block;
//
//    // rotate the bitset by 'rhs' places
//    let (a, b) = bitset.as_slice().split_at(num_blocks_shift);
//    let mut blocks: Vec<u32> = vec![];
//    blocks.extend_from_slice(b);
//    blocks.extend_from_slice(a);
//
//    FixedBitSet::with_capacity_and_blocks(bitset.len(), blocks)
//}

//impl BeamHashIII_StepElement {
//    pub fn new(pre_pow: &[u8], index: u32) -> Self {
//        //let mut work_bits = FixedBitSet::with_capacity(BEAM_HASH_III_WORK_BIT_SIZE);
//        //let mut work_bits = bitarr![Lsb0, u8; 0; BEAM_HASH_III_WORK_BIT_SIZE];
//        let mut work_bits: BitArray<LocalBits, [usize; 0]> = bitarr![];
//
//        // We need to start from 6
//        for i in (0..=6).rev() {
//            let nonce = (index << 3) + i;
//
//            work_bits.rotate_left(64);
//            //let or2 = BitArray::new(data);
//            //let or_rhs = BitSlice::from_element(&2u64);
//            //work_bits = &work_bits | or_rhs;
//
//            //work_bits = work_bits << 64;
//            //work_bits = bitset_shl(work_bits, 64);
//            //work_bits |= 2u64;
//        }
//
//        BeamHashIII_StepElement {
//            work_bits: work_bits,
//            index_tree: vec![],
//        }
//    }
//
//    pub fn from(a: &Self, b: &Self, remaining_len: u32) {
//    }
//}

#[test]
fn test_beam_hash3_blake2b_personalization() {
    let mut personalization: Vec<u8> = Vec::new();
    personalization.put(&b"Beam-PoW"[..]);
    personalization.put_u32_le(BEAM_HASH_III_WORK_BIT_SIZE as u32);
    personalization.put_u32_le(BEAM_HASH_III_NUM_ROUNDS as u32);

    let expected_personalization = &[
        0x42, 0x65, 0x61, 0x6d, 0x2d, 0x50, 0x6f, 0x57,
        0xc0, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    ];
    assert_eq!(personalization.as_slice(), expected_personalization);
}

#[test]
fn test_beam_hash3_blake2b_state() {
    // Test vector: "abc"
    let data = vec![0x61, 0x62, 0x63];
    let mut state = BeamHashIII::initialize_state();
    state.update(&data);

    let expected_hash = &[
        0x02, 0x67, 0x75, 0x4a, 0xeb, 0x00, 0xb8, 0x7b,
        0x44, 0x66, 0xe8, 0x14, 0xd4, 0xd4, 0x19, 0x4c,
        0xda, 0x10, 0xf6, 0x6a, 0xdd, 0xbc, 0x2d, 0x3f,
        0x42, 0x71, 0x2d, 0x18, 0xcd, 0xd6, 0x1a, 0xc5,
    ];
    let hash = state.finalize();
    assert_eq!(expected_hash, &hash.as_bytes());
}

use crate::util::{find_fork};

use frame_support::{debug};
use core::ops::{Shl, Shr, BitAnd};
use core::hash::Hasher;

use blake2b_simd::{
    State as Blake2b_State,
    Params as Blake2b_Params,
};
use siphasher::sip::BeamSipHasher24;
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
    work_bits: BitVec::<Lsb0, usize>,
    index_tree: Vec<u32>,
    //work_bits: BitArray<LocalBits, [usize; 1]>,
}

fn get_bit_at(input: u8, n: u8) -> bool {
    if n < 8 {
        input & (1 << n) != 0
    } else {
        false
    }
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

        if cfg!(test) {
            //assert_eq!("Blake2b hash: {:?}", &hash.to_hex());
        }
        debug::info!("Blake2b hash: {:?}", &hash.to_hex());

        let mut pre_pow = hash.as_bytes();

        let indices = BeamPowHelper::get_indices_from_minimal(solution);
        let mut steps: Vec<BeamHashIII_StepElement> = Vec::new();
        for i in 0..indices.len() {
            steps.push(BeamHashIII_StepElement::new(pre_pow, indices[i]));
            break;
        }
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

    pub fn get_indices_from_minimal(pow_solution: &[u8]) -> Vec<u32> {
        let num_collision_bits = BEAM_HASH_III_COLLISION_BIT_SIZE as usize + 1;
        let num_chunks = 32_usize;
        let chunk_size = 32_usize;

        let mut in_stream = bitvec![Msb0, u8; 0; 800];
        in_stream.reserve(num_chunks * (chunk_size - num_collision_bits));

        let num_bytes_to_process = 100;
        let rev_solution = pow_solution[0..num_bytes_to_process]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<u8>>();

        // Fill with bytes from the reversed solution
        for i in 0..num_bytes_to_process {
            for j in 0..8 {
                in_stream.set(i * 8 + (7 - j), get_bit_at(rev_solution[i], j as u8));
            }
        }

        // During processing we expect that the first bit in each chunk represents
        // the whole first byte with ommitted zeroes on the left.
        // Add additional 7 leading zeroes to each chunk, so we can operate
        // with 32-bits chunks thus easily convert each chunk to u32.
        for i in 0..num_chunks {
            let pos = i * chunk_size;
            for _ in 0..(chunk_size - num_collision_bits) {
                in_stream.insert(pos, false);
            }
        }
        let mut res: Vec<u32> = Vec::new();
        let mut chunks = in_stream.as_bitslice().chunks_exact(chunk_size);
        for i in 0..num_chunks {
            let mut value_bits = chunks.next().unwrap();

            let mut value_arr: [u8; 4] = Default::default();
            value_arr.copy_from_slice(value_bits.as_slice());
            let value = u32::from_be_bytes(value_arr);

            res.push(value);
        }
        res.reverse();

        res
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

//fn bitvec_shr(bitvec: BitVec::<Msb0, u8>, shift: usize) -> BitVec::<Msb0, u8> {
//    let mut vec = bitvec.clone();
//    for _ in 0..shift {
//        vec.insert(0, false);
//    }
//    return vec;
//}

impl BeamHashIII_StepElement {
    pub fn new(pre_pow: &[u8], index: u32) -> Self {
        //let mut work_bits = bitvec!();
        let mut work_bits = bitvec![Lsb0, usize; 0; 0];

        // We need to start from 6
        for i in (0..=6).rev() {
            let nonce = (index << 3) + i;

            let mut hasher = BeamSipHasher24::new_with_nonce(nonce.into());
            hasher.set_state_from_bytes(pre_pow);
            let hash = hasher.finish();

            if i == 6 && cfg!(test) {
                let expected_pow_state = &[
                    0xc0, 0x9d, 0xd9, 0x3e, 0xf2, 0x5c, 0xdb, 0xa0,
                    0x95, 0xc9, 0x9f, 0xab, 0x3c, 0x5f, 0xfb, 0xac,
                    0x3e, 0x72, 0xaf, 0x34, 0x96, 0xd8, 0xb4, 0x8d,
                    0x03, 0x04, 0xf6, 0xf2, 0xac, 0x18, 0x98, 0x68
                ];
                let expected_nonce = 3414214;
                let expected_hash = 12899870395040861258 as u64;
                assert_eq!(expected_pow_state, pre_pow);
                assert_eq!(expected_nonce, nonce);
                assert_eq!(expected_hash, hash);
            }

            let hash_bytes = hash.to_le_bytes();

            for byte in &hash_bytes {
                for i in 0..8 {
                    work_bits.push(get_bit_at(*byte, i));
                }
            }
        }

        if cfg!(test) {
            //assert_eq!(&[0usize, 1usize], work_bits.as_slice());
        }

        let mut index_tree: Vec<u32> = Vec::new();
        index_tree.push(index);

        BeamHashIII_StepElement {
            work_bits: work_bits,
            index_tree: index_tree,
        }
    }

    pub fn from(a: &Self, b: &Self, remaining_len: u32) {
    }
}

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
    let data = &[0x61, 0x62, 0x63];
    let mut state = BeamHashIII::initialize_state();
    state.update(data);

    let expected_hash = &[
        0x02, 0x67, 0x75, 0x4a, 0xeb, 0x00, 0xb8, 0x7b,
        0x44, 0x66, 0xe8, 0x14, 0xd4, 0xd4, 0x19, 0x4c,
        0xda, 0x10, 0xf6, 0x6a, 0xdd, 0xbc, 0x2d, 0x3f,
        0x42, 0x71, 0x2d, 0x18, 0xcd, 0xd6, 0x1a, 0xc5,
    ];
    let hash = state.finalize();
    assert_eq!(expected_hash, &hash.as_bytes());
}

#[test]
fn test_beam_hash3_pow_solution_blake2b_hashing() -> Result<(), String> {
    // Test input vector (basically it's the hash of the block without PoW part)
    let input = &[
        0xa0, 0x5e, 0xa9, 0xb3, 0xdd, 0x32, 0x9b, 0xbf,
        0x3e, 0x8e, 0xf6, 0x84, 0x15, 0xea, 0xe1, 0x02,
        0x02, 0x1f, 0x1d, 0x9a, 0x99, 0x5d, 0x4a, 0x72,
        0x7c, 0xb3, 0xe3, 0x07, 0xe5, 0xd1, 0x73, 0x21,
    ];
    // Test PoW nonce vector
    let nonce = &[0xad, 0x63, 0x64, 0x76, 0xf7, 0x11, 0x74, 0x00];
    // Test solution vector
    let solution = &[0x00, 0x00, 0x00, 0x00];
    // Test height for the solution
    let height = 903720;

    let mut state = BeamPowHelper::reset(input, nonce, height)
        .ok_or_else(|| "Can't call BeamPowHelper::reset using provided args. State is None")?;
    state.update(solution);

    let hash = state.finalize();
    let expected_hash = &[
        0xc0, 0x9d, 0xd9, 0x3e, 0xf2, 0x5c, 0xdb, 0xa0,
        0x95, 0xc9, 0x9f, 0xab, 0x3c, 0x5f, 0xfb, 0xac,
        0x3e, 0x72, 0xaf, 0x34, 0x96, 0xd8, 0xb4, 0x8d,
        0x03, 0x04, 0xf6, 0xf2, 0xac, 0x18, 0x98, 0x68,
    ];

    assert_eq!(expected_hash, &hash.as_bytes());

    Ok(())
}

#[test]
fn test_beam_hash3_is_valid_solution() -> Result<(), String> {
    // Test input vector (basically it's the hash of the block without PoW part)
    let input = &[
        0xa0, 0x5e, 0xa9, 0xb3, 0xdd, 0x32, 0x9b, 0xbf,
        0x3e, 0x8e, 0xf6, 0x84, 0x15, 0xea, 0xe1, 0x02,
        0x02, 0x1f, 0x1d, 0x9a, 0x99, 0x5d, 0x4a, 0x72,
        0x7c, 0xb3, 0xe3, 0x07, 0xe5, 0xd1, 0x73, 0x21,
    ];
    // Test PoW nonce vector
    let pow_nonce = &[0xad, 0x63, 0x64, 0x76, 0xf7, 0x11, 0x74, 0x00];
    // Test solution vector
    let pow_solution = &[
        0x18, 0x83, 0x06, 0x06, 0x8a, 0xf6, 0x92, 0xbd, 0xd9, 0xd4, 0x03, 0x55, 0xee, 0xca, 0x86,
        0x40, 0x00, 0x5a, 0xa7, 0xff, 0x65, 0xb6, 0x1a, 0x85, 0xb4, 0x5f, 0xc7, 0x0a, 0x8a, 0x2a,
        0xc1, 0x27, 0xdb, 0x2d, 0x90, 0xc4, 0xfc, 0x39, 0x76, 0x43, 0xa5, 0xd9, 0x8f, 0x3e, 0x64,
        0x4f, 0x9f, 0x59, 0xfc, 0xf9, 0x67, 0x7a, 0x0d, 0xa2, 0xe9, 0x0f, 0x59, 0x7f, 0x61, 0xa1,
        0xbf, 0x17, 0xd6, 0x75, 0x12, 0xc6, 0xd5, 0x7e, 0x68, 0x0d, 0x0a, 0xa2, 0x64, 0x2f, 0x7d,
        0x27, 0x5d, 0x27, 0x00, 0x18, 0x8d, 0xbf, 0x8b, 0x43, 0xfa, 0xc5, 0xc8, 0x8f, 0xa0, 0x8f,
        0xa2, 0x70, 0xe8, 0xd8, 0xfb, 0xc3, 0x37, 0x77, 0x61, 0x9b, 0x00, 0x00, 0x00, 0x00,
    ];
    // Test height for the solution
    let height = 903720;

    let mut state = BeamPowHelper::reset(input, pow_nonce, height)
        .ok_or_else(|| "Can't call BeamPowHelper::reset using provided args. State is None")?;
    //BeamHashIII::is_valid_solution(&state, pow_solution);

    Ok(())
}

#[test]
fn test_beam_pow_helper_get_indices_from_minimal_raw() -> Result<(), String> {
    let pow_solution = &[
        0x18, 0x83, 0x06, 0x06, 0x8a, 0xf6, 0x92, 0xbd, 0xd9, 0xd4, 0x03, 0x55, 0xee, 0xca, 0x86,
        0x40, 0x00, 0x5a, 0xa7, 0xff, 0x65, 0xb6, 0x1a, 0x85, 0xb4, 0x5f, 0xc7, 0x0a, 0x8a, 0x2a,
        0xc1, 0x27, 0xdb, 0x2d, 0x90, 0xc4, 0xfc, 0x39, 0x76, 0x43, 0xa5, 0xd9, 0x8f, 0x3e, 0x64,
        0x4f, 0x9f, 0x59, 0xfc, 0xf9, 0x67, 0x7a, 0x0d, 0xa2, 0xe9, 0x0f, 0x59, 0x7f, 0x61, 0xa1,
        0xbf, 0x17, 0xd6, 0x75, 0x12, 0xc6, 0xd5, 0x7e, 0x68, 0x0d, 0x0a, 0xa2, 0x64, 0x2f, 0x7d,
        0x27, 0x5d, 0x27, 0x00, 0x18, 0x8d, 0xbf, 0x8b, 0x43, 0xfa, 0xc5, 0xc8, 0x8f, 0xa0, 0x8f,
        0xa2, 0x70, 0xe8, 0xd8, 0xfb, 0xc3, 0x37, 0x77, 0x61, 0x9b, 0x00, 0x00, 0x00, 0x00,
    ];

    let num_collision_bits = BEAM_HASH_III_COLLISION_BIT_SIZE as usize + 1;
    let num_chunks = 32_usize;
    let chunk_size = 32_usize;
    let mut in_stream = bitvec![Msb0, u8; 0; 800];
    in_stream.reserve(num_chunks * (chunk_size - num_collision_bits));

    let num_bytes_to_process = 100;
    let rev_solution = pow_solution[0..num_bytes_to_process]
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<u8>>();

    // Fill with bytes from the reversed solution
    for i in 0..num_bytes_to_process {
        for j in 0..8 {
            in_stream.set(i * 8 + (7 - j), get_bit_at(rev_solution[i], j as u8));
        }
    }
    //println!("Instream: {}", &in_stream);

    // During processing we expect that the first bit in each chunk represents
    // the whole first byte with ommitted zeroes on the left.
    // Add additional 7 leading zeroes to each chunk, so we can operate
    // with 32-bits chunks thus easily convert each chunk to u32.
    for i in 0..num_chunks {
        let pos = i * chunk_size;
        for _ in 0..(chunk_size - num_collision_bits) {
            in_stream.insert(pos, false);
        }
    }
    //println!("Instream updated with size {}: {}", in_stream.len(), &in_stream);

    let mut res: Vec<u32> = Vec::new();
    let mut chunks = in_stream.as_bitslice().chunks_exact(chunk_size);
    for i in 0..num_chunks {
        let mut value_bits = chunks.next().unwrap();
        //println!("Chunk value bits: {:?}", value_bits.as_slice());

        let mut value_arr: [u8; 4] = Default::default();
        value_arr.copy_from_slice(value_bits.as_slice());
        //println!("Chunk value array: {:?}", value_arr);
        let value = u32::from_be_bytes(value_arr);
        //println!("Value: {}", value);

        res.push(value);
    }
    res.reverse();

    let expected_res = &[
        426776, 24855811, 20344676, 30056570, 552110, 20631554, 14260222, 23661109,
        706399, 31495493, 751305, 20945042, 5519203, 32800461, 8207760, 32766131,
        883303, 8910033, 5791702, 12777460, 6367069, 21231278, 8923189, 16408265,
        2579751, 29789184, 9495279, 33102015, 2685448, 13058949, 14618607, 20366062,
    ];
    assert_eq!(res, expected_res);

    println!("Res: {:?}", &res);

    Ok(())
}

#[test]
fn test_beam_pow_helper_get_indices_from_minimal() {
    let pow_solution = &[
        0x18, 0x83, 0x06, 0x06, 0x8a, 0xf6, 0x92, 0xbd, 0xd9, 0xd4, 0x03, 0x55, 0xee, 0xca, 0x86,
        0x40, 0x00, 0x5a, 0xa7, 0xff, 0x65, 0xb6, 0x1a, 0x85, 0xb4, 0x5f, 0xc7, 0x0a, 0x8a, 0x2a,
        0xc1, 0x27, 0xdb, 0x2d, 0x90, 0xc4, 0xfc, 0x39, 0x76, 0x43, 0xa5, 0xd9, 0x8f, 0x3e, 0x64,
        0x4f, 0x9f, 0x59, 0xfc, 0xf9, 0x67, 0x7a, 0x0d, 0xa2, 0xe9, 0x0f, 0x59, 0x7f, 0x61, 0xa1,
        0xbf, 0x17, 0xd6, 0x75, 0x12, 0xc6, 0xd5, 0x7e, 0x68, 0x0d, 0x0a, 0xa2, 0x64, 0x2f, 0x7d,
        0x27, 0x5d, 0x27, 0x00, 0x18, 0x8d, 0xbf, 0x8b, 0x43, 0xfa, 0xc5, 0xc8, 0x8f, 0xa0, 0x8f,
        0xa2, 0x70, 0xe8, 0xd8, 0xfb, 0xc3, 0x37, 0x77, 0x61, 0x9b, 0x00, 0x00, 0x00, 0x00,
    ];
    let indices = BeamPowHelper::get_indices_from_minimal(pow_solution);

    let expected_indices = &[
        426776, 24855811, 20344676, 30056570, 552110, 20631554, 14260222, 23661109,
        706399, 31495493, 751305, 20945042, 5519203, 32800461, 8207760, 32766131,
        883303, 8910033, 5791702, 12777460, 6367069, 21231278, 8923189, 16408265,
        2579751, 29789184, 9495279, 33102015, 2685448, 13058949, 14618607, 20366062,
    ];
    assert_eq!(indices, expected_indices);

    println!("Get indices from minimal test is successful!");
}

#[test]
fn test_beam_hash3_step_element_new_from_prepow() -> Result<(), String> {
    // Test input vector (basically it's the hash of the block without PoW part)
    let input = &[
        0xa0, 0x5e, 0xa9, 0xb3, 0xdd, 0x32, 0x9b, 0xbf,
        0x3e, 0x8e, 0xf6, 0x84, 0x15, 0xea, 0xe1, 0x02,
        0x02, 0x1f, 0x1d, 0x9a, 0x99, 0x5d, 0x4a, 0x72,
        0x7c, 0xb3, 0xe3, 0x07, 0xe5, 0xd1, 0x73, 0x21,
    ];
    // Test PoW nonce vector
    let pow_nonce = &[0xad, 0x63, 0x64, 0x76, 0xf7, 0x11, 0x74, 0x00];
    // Test solution vector
    let pow_solution = &[
        0x18, 0x83, 0x06, 0x06, 0x8a, 0xf6, 0x92, 0xbd, 0xd9, 0xd4, 0x03, 0x55, 0xee, 0xca, 0x86,
        0x40, 0x00, 0x5a, 0xa7, 0xff, 0x65, 0xb6, 0x1a, 0x85, 0xb4, 0x5f, 0xc7, 0x0a, 0x8a, 0x2a,
        0xc1, 0x27, 0xdb, 0x2d, 0x90, 0xc4, 0xfc, 0x39, 0x76, 0x43, 0xa5, 0xd9, 0x8f, 0x3e, 0x64,
        0x4f, 0x9f, 0x59, 0xfc, 0xf9, 0x67, 0x7a, 0x0d, 0xa2, 0xe9, 0x0f, 0x59, 0x7f, 0x61, 0xa1,
        0xbf, 0x17, 0xd6, 0x75, 0x12, 0xc6, 0xd5, 0x7e, 0x68, 0x0d, 0x0a, 0xa2, 0x64, 0x2f, 0x7d,
        0x27, 0x5d, 0x27, 0x00, 0x18, 0x8d, 0xbf, 0x8b, 0x43, 0xfa, 0xc5, 0xc8, 0x8f, 0xa0, 0x8f,
        0xa2, 0x70, 0xe8, 0xd8, 0xfb, 0xc3, 0x37, 0x77, 0x61, 0x9b, 0x00, 0x00, 0x00, 0x00,
    ];
    // Test height for the solution
    let height = 903720;

    let mut state = BeamPowHelper::reset(input, pow_nonce, height)
        .ok_or_else(|| "Can't call BeamPowHelper::reset using provided args. State is None")?;

    // Last 4 bytes of solution are our extra nonce
    state.update(&pow_solution[100..104]);
    let hash = state.finalize();

    let pre_pow = hash.as_bytes();
    let indices = BeamPowHelper::get_indices_from_minimal(pow_solution);
    let mut steps: Vec<BeamHashIII_StepElement> = Vec::new();
    for i in 0..indices.len() {
        steps.push(BeamHashIII_StepElement::new(pre_pow, indices[i]));
        break;
    }
    println!("Step 0: {}", steps[0].work_bits);
    println!("Step 0 MSB: {}", steps[0].work_bits.as_raw_slice().view_bits::<Msb0>());

    Ok(())
}

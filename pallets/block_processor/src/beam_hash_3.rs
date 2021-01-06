use crate::util::{find_fork};

use frame_support::{debug};
use core::hash::Hasher;

use blake2b_simd::{
    State as Blake2b_State,
    Params as Blake2b_Params,
};
use siphasher::sip::BeamSipHasher24;
use bitvec::prelude::*;
use bytes::{BufMut};

use sp_std::{
    vec::Vec,
};

const BEAM_HASH_3_WORK_BIT_SIZE: usize = 448;
const BEAM_HASH_3_WORK_BYTES: usize = BEAM_HASH_3_WORK_BIT_SIZE / 8;
const BEAM_HASH_3_WORK_WORDS: usize = BEAM_HASH_3_WORK_BYTES / 8;
const BEAM_HASH_3_COLLISION_BIT_SIZE: usize = 24;
const BEAM_HASH_3_NUM_ROUNDS: usize = 5;
const BEAM_HASH_3_SOL_SIZE: usize = 104;


pub struct BeamHash3;

#[derive(Default, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BeamPowHelper {
    blake_state: Blake2b_State
}

#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
#[allow(non_camel_case_types)]
struct BeamHash3_StepElement {
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

impl BeamHash3 {
    pub fn initialize_state() -> Blake2b_State {
        let mut personalization: Vec<u8> = Vec::new();
        personalization.put(&b"Beam-PoW"[..]);
        personalization.put_u32_le(BEAM_HASH_3_WORK_BIT_SIZE as u32);
        personalization.put_u32_le(BEAM_HASH_3_NUM_ROUNDS as u32);

        debug::info!("Blake2b personalization: {:x?}", personalization.as_slice());

        Blake2b_Params::new()
            .hash_length(32)
            .fanout(1)
            .max_depth(1)
            .personal(&personalization)
            .to_state()
    }

    pub fn is_valid_solution(base_state: &Blake2b_State, solution: &[u8]) -> bool {
        if solution.len() != BEAM_HASH_3_SOL_SIZE {
            return false;
        }

        let mut state = base_state.clone();
        // Last 4 bytes of solution are our extra nonce
        state.update(&solution[BEAM_HASH_3_SOL_SIZE - 4..]);
        let hash = state.finalize();

        debug::info!("Blake2b hash: {:?}", &hash.to_hex());

        let pre_pow = hash.as_bytes();

        let indices = BeamPowHelper::get_indices_from_minimal(solution);
        let mut steps: Vec<BeamHash3_StepElement> = Vec::new();
        for i in 0..indices.len() {
            steps.push(BeamHash3_StepElement::new(pre_pow, indices[i]));
        }

        let mut round = 1;
        let mut step = 1;
        while step < indices.len() {
            let mut i0 = 0;
            while i0 < indices.len() {
                let mut remaining_len = BEAM_HASH_3_WORK_BIT_SIZE as u32 - (round - 1)*BEAM_HASH_3_COLLISION_BIT_SIZE as u32;
                if round == 5 {
                    remaining_len -= 64;
                }

                steps[i0].apply_mix(remaining_len, &indices[i0..], step);

                let i1 = i0 + step;
                steps[i1].apply_mix(remaining_len, &indices[i1..], step);

                if !steps[i0].has_collision(&steps[i1]) {
                    if cfg!(test) {
                        assert_eq!("Collision error!", "");
                    }

                    return false;
                }

                if indices[i0] >= indices[i1] {
                    if cfg!(test) {
                        assert_eq!("Non-distinct indices error!", "");
                    }

                    return false;
                }

                remaining_len = BEAM_HASH_3_WORK_BIT_SIZE as u32 - round*BEAM_HASH_3_COLLISION_BIT_SIZE as u32;
                if round == 4 {
                    remaining_len -= 64;
                } else if round == 5 {
                    remaining_len = BEAM_HASH_3_COLLISION_BIT_SIZE as u32;
                }

                let step_i1 = steps[i1].clone();
                steps[i0].merge_with(&step_i1, remaining_len);

                i0 = i1 + step;
            }

            step <<= 1;
            round += 1;
        }

        steps[0].is_zero()
    }
}

impl BeamPowHelper {
    pub fn reset(input: &[u8], nonce: &[u8], height: u64) -> Option<Blake2b_State> {
        // Everything but BeamHash3 is not supported
        if find_fork(height) < 2 {
            return None;
        }

        let mut state = BeamHash3::initialize_state();
        state.update(input);
        state.update(nonce);

        Some(state)
    }

    pub fn get_indices_from_minimal(pow_solution: &[u8]) -> Vec<u32> {
        let num_collision_bits = BEAM_HASH_3_COLLISION_BIT_SIZE as usize + 1;
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
        for _ in 0..num_chunks {
            let value_bits = chunks.next().unwrap();

            let mut value_arr: [u8; 4] = Default::default();
            value_arr.copy_from_slice(value_bits.as_slice());
            let value = u32::from_be_bytes(value_arr);

            res.push(value);
        }
        res.reverse();

        res
    }
}

impl BeamHash3_StepElement {
    pub fn new(pre_pow: &[u8], index: u32) -> Self {
        let mut work_bits = bitvec![Lsb0, usize; 0; 0];

        // We need to start from 6
        for i in (0..=6).rev() {
            let nonce = (index << 3) + i;

            let mut hasher = BeamSipHasher24::new_with_nonce(nonce.into());
            hasher.set_state_from_bytes(pre_pow);
            let hash = hasher.finish();

            let hash_bytes = hash.to_le_bytes();

            for byte in &hash_bytes {
                for i in 0..8 {
                    work_bits.push(get_bit_at(*byte, i));
                }
            }
        }

        let mut index_tree: Vec<u32> = Vec::new();
        index_tree.push(index);

        BeamHash3_StepElement {
            work_bits: work_bits,
            index_tree: index_tree,
        }
    }

    pub fn merge_with(&mut self, other: &Self, remaining_len: u32) -> bool {
        if remaining_len % 8 != 0 {
            return false;
        }

        self.work_bits ^= other.work_bits.clone();

        let work_bits = self.work_bits.as_mut_raw_slice().view_bits_mut::<Msb0>();
        work_bits.rotate_right(BEAM_HASH_3_COLLISION_BIT_SIZE);
        work_bits[..BEAM_HASH_3_WORK_BIT_SIZE-remaining_len as usize].set_all(false);

        true
    }

    pub fn apply_mix(&mut self, remaining_len: u32, indices: &[u32], step: usize) {
        let work_word_size = 8;

        let work_bits = self.work_bits.clone();
        // This should have the size of 9
        let mut temp_words: Vec<usize> = Vec::new();
        temp_words.extend_from_slice(work_bits.as_raw_slice().view_bits::<Msb0>().as_slice());
        temp_words.reverse();
        temp_words.push(0);
        temp_words.push(0);

        let mut pad_num = ((512 - remaining_len) + BEAM_HASH_3_COLLISION_BIT_SIZE as u32) / (BEAM_HASH_3_COLLISION_BIT_SIZE as u32 + 1);
        if pad_num > step as u32 {
            pad_num = step as u32;
        }

        for i in 0..pad_num as usize {
            let mut shift = remaining_len as usize + i * (BEAM_HASH_3_COLLISION_BIT_SIZE + 1);
            let n0 = shift / (work_word_size * 8);
            shift %= work_word_size * 8;

            let index = indices[i];

            temp_words[n0] |= ((index as u64) << (shift as u32)) as usize;

            if shift + BEAM_HASH_3_COLLISION_BIT_SIZE + 1 > work_word_size * 8 {
                temp_words[n0 + 1] |= (index >> (work_word_size * 8 - shift)) as usize;
            }
        }

        // Applying the mix from the lined up bits
        let mut result = 0u64;
        for i in 0..8 {
            let word = temp_words[i] as u64;
            let word_rotated = word.rotate_left((29 * (i as u32 + 1)) & 0x3F);
            result = result.overflowing_add(word_rotated).0;
        }

        result = result.rotate_left(24);

        // Wipe out lowest 64 bits in favor of the mixed bits
        //let result_bits = BitSlice::<Lsb0, _>::from_element(&result);
        //self.work_bits.as_mut_bitslice()[0..work_word_size * 8] = result_bits;
        self.work_bits.as_mut_raw_slice()[BEAM_HASH_3_WORK_WORDS - 1] = result as usize;
    }

    fn get_collision_bits(&self) -> &BitSlice<Msb0, usize> {
        &self.work_bits.as_raw_slice().view_bits::<Msb0>()[BEAM_HASH_3_WORK_BIT_SIZE-BEAM_HASH_3_COLLISION_BIT_SIZE..]
    }

    pub fn has_collision(&self, other: &Self) -> bool {
        self.get_collision_bits() == other.get_collision_bits()
    }

    pub fn is_zero(&self) -> bool {
        !self.work_bits.any()
    }
}

#[test]
fn test_beam_hash3_blake2b_personalization() {
    let mut personalization: Vec<u8> = Vec::new();
    personalization.put(&b"Beam-PoW"[..]);
    personalization.put_u32_le(BEAM_HASH_3_WORK_BIT_SIZE as u32);
    personalization.put_u32_le(BEAM_HASH_3_NUM_ROUNDS as u32);

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
    let mut state = BeamHash3::initialize_state();
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

    let state = BeamPowHelper::reset(input, pow_nonce, height)
        .ok_or_else(|| "Can't call BeamPowHelper::reset using provided args. State is None")?;
    let is_valid_solution = BeamHash3::is_valid_solution(&state, pow_solution);
    assert!(is_valid_solution);

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

    let num_collision_bits = BEAM_HASH_3_COLLISION_BIT_SIZE as usize + 1;
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
    for _ in 0..num_chunks {
        let value_bits = chunks.next().unwrap();

        let mut value_arr: [u8; 4] = Default::default();
        value_arr.copy_from_slice(value_bits.as_slice());
        let value = u32::from_be_bytes(value_arr);

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
    state.update(&pow_solution[BEAM_HASH_3_SOL_SIZE - 4..]);
    let hash = state.finalize();

    let pre_pow = hash.as_bytes();
    let indices = BeamPowHelper::get_indices_from_minimal(pow_solution);
    let mut steps: Vec<BeamHash3_StepElement> = Vec::new();
    for i in 0..indices.len() {
        steps.push(BeamHash3_StepElement::new(pre_pow, indices[i]));
        break;
    }
    println!("Step 0: {}", steps[0].work_bits);
    println!("Step 0 MSB: {}", steps[0].work_bits.as_raw_slice().view_bits::<Msb0>());

    Ok(())
}

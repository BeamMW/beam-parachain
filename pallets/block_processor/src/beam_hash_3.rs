use crate::util::{find_fork};

use blake2b_simd::{
    State as Blake2b_State,
    Params as Blake2b_Params,
};
use bytes::{BufMut};

use sp_std::{
    vec::Vec,
};

const BEAM_HASH_III_WORK_BIT_SIZE: u32 = 448;
const BEAM_HASH_III_COLLISION_BIT_SIZE: u32 = 24;
const BEAM_HASH_III_NUM_ROUNDS: u32 = 5;
const BEAM_HASH_III_SOL_SIZE: u32 = 104;


#[derive(Default, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BeamPowHelper {
    pub blake_state: Blake2b_State
}

pub struct BeamHashIII;

impl BeamHashIII {
    pub fn initialize_state() -> Blake2b_State {
        let mut personalization: Vec<u8> = Vec::new();
        personalization.put(&b"Beam-PoW"[..]);
        personalization.put_u32(BEAM_HASH_III_WORK_BIT_SIZE);
        personalization.put_u32(BEAM_HASH_III_NUM_ROUNDS);

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

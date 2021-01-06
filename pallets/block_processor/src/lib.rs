#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

mod block;
mod beam_hash_3;
mod util;

//#[macro_use]
//extern crate libc_print;

#[macro_use]
extern crate bitvec;

#[macro_use]
extern crate alloc;

use frame_support::{decl_module, decl_storage, decl_event, decl_error, ensure, dispatch, traits::Get, debug};
use frame_system::ensure_signed;
use sp_std::vec::Vec;
use crate::block::{PoW, BeamBlockHeader};
use frame_support::codec::{Encode};
use sp_core::H256;


/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Trait: frame_system::Trait {
    /// Because this pallet emits events, it depends on the runtime's definition of an event.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
    trait Store for Module<T: Trait> as BeamBlockProcessor {
        // Learn more about declaring storage items:
        // https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
        /// The storage item for beam block headers.
        /// It maps block header hash to the block header.
        BlockHeader get(fn block_header): map hasher(identity) H256 => BeamBlockHeader;
        /// The storage item for beam block headers uploaders
        /// It maps account ID to the block header's hash
        BlockHeaderUploader get(fn block_header_uploader): map hasher(identity) H256 => T::AccountId;
    }
}

// Pallets use events to inform users when important changes are made.
// Event documentation should end with an array that provides descriptive names for parameters.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!(
    pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
        /// Event emitted when a new block header is submitted. [who, block_header_hash]
        BlockHeaderStored(AccountId, H256),
    }
);

// Errors inform users that something went wrong.
decl_error! {
    pub enum Error for Module<T: Trait> {
        /// The block header has already been stored
        BlockHeaderAlreadyStored,
        /// The block header has invalid PoW
        BlockHeaderInvalidProofOfWork,
        /// The block header hasn't been stored yet
        BlockHeaderDoesntExist,
        /// The block is having old hash type
        BlockHeaderOldHashType,
    }
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Errors must be initialized if they are used by the pallet.
        type Error = Error<T>;

        // Events must be initialized if they are used by the pallet.
        fn deposit_event() = default;

        /// Allow a user to store a beam block header.
        #[weight = 10_000 + T::DbWeight::get().reads_writes(1,1)]
        pub fn store_block_header(origin,
            height: u64,
            prev: Vec<u8>,
            chain_work: Vec<u8>,
            kernels: Vec<u8>,
            definition: Vec<u8>,
            timestamp: u64,
            pow: Vec<u8>,
        ) -> dispatch::DispatchResult {
            // Check that the extrinsic was signed and get the signer.
            // This function will return an error if the extrinsic is not signed.
            // https://substrate.dev/docs/en/knowledgebase/runtime/origin
            let sender = ensure_signed(origin)?;

            let pow = PoW::from_bytes(&pow);
            let block_header = BeamBlockHeader::new(
                height,
                prev,
                chain_work,
                kernels,
                definition,
                timestamp,
                pow,
            );
            let block_header_hash = block_header.get_hash();
            debug::info!("Calculated block header hash: {:X?}", block_header_hash.as_bytes());
            debug::info!("Is valid PoW: {}", block_header.is_valid_pow());

            // Verify that the specified block header has valid pow
            ensure!(block_header.is_valid_pow(), Error::<T>::BlockHeaderInvalidProofOfWork);

            // Verify that the specified block header has not already been stored.
            ensure!(!BlockHeader::contains_key(&block_header_hash), Error::<T>::BlockHeaderAlreadyStored);

            // Store the block header with the block header hash.
            BlockHeader::insert(&block_header_hash, block_header);
            // Store the block header's hash with the sender.
            <BlockHeaderUploader<T>>::insert(&block_header_hash, &sender);

            // Emit an event that the block header was stored.
            Self::deposit_event(RawEvent::BlockHeaderStored(sender, block_header_hash));

            Ok(())
        }
    }
}

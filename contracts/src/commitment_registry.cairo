use starknet::ContractAddress;

#[starknet::interface]
pub trait ICommitmentRegistry<TContractState> {
    fn set_batch_registrar(ref self: TContractState, registrar: ContractAddress);
    fn set_privacy_deposit_bridge(ref self: TContractState, bridge: ContractAddress);
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn register_order_commitments(
        ref self: TContractState, batch_id: felt252, commitments: Span<felt252>,
    );
    fn register_note_commitments(
        ref self: TContractState, batch_id: felt252, commitments: Span<felt252>,
    );
    fn register_deposit_note_commitment(ref self: TContractState, commitment: felt252);
    fn is_order_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_note_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn order_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn note_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn batch_registrar_address(self: @TContractState) -> ContractAddress;
    fn privacy_deposit_bridge_address(self: @TContractState) -> ContractAddress;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CommitmentRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::auction_verifier::{
        IAuctionVerifierDispatcher, IAuctionVerifierDispatcherTrait,
    };

    #[storage]
    struct Storage {
        admin: ContractAddress,
        batch_registrar: ContractAddress,
        privacy_deposit_bridge: ContractAddress,
        auction_verifier: ContractAddress,
        order_commitments: Map<felt252, bool>,
        order_commitment_batch_ids: Map<felt252, felt252>,
        note_commitments: Map<felt252, bool>,
        note_commitment_batch_ids: Map<felt252, felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl CommitmentRegistryImpl of super::ICommitmentRegistry<ContractState> {
        fn set_batch_registrar(ref self: ContractState, registrar: ContractAddress) {
            assert_admin(@self);
            assert(!registrar.is_zero(), 'BAD_REGISTRAR');
            self.batch_registrar.write(registrar);
        }

        fn set_privacy_deposit_bridge(ref self: ContractState, bridge: ContractAddress) {
            assert_admin(@self);
            assert(!bridge.is_zero(), 'BAD_PRIVACY_BRIDGE');
            self.privacy_deposit_bridge.write(bridge);
        }

        fn set_auction_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert_admin(@self);
            assert(!verifier.is_zero(), 'BAD_AUCTION_VERIFIER');
            self.auction_verifier.write(verifier);
        }

        fn register_order_commitments(
            ref self: ContractState, batch_id: felt252, commitments: Span<felt252>,
        ) {
            assert_batch_registrar(@self);
            assert(batch_id != 0, 'BAD_BATCH_ID');
            let mut index = 0;
            let len = commitments.len();
            loop {
                if index == len {
                    break;
                }

                let commitment = *commitments.at(index);
                assert(commitment != 0, 'BAD_COMMITMENT');
                let exists = self.order_commitments.read(commitment);
                assert(exists == false, 'ORDER_EXISTS');
                self.order_commitments.write(commitment, true);
                self.order_commitment_batch_ids.write(commitment, batch_id);
                index += 1;
            };
        }

        fn register_note_commitments(
            ref self: ContractState, batch_id: felt252, commitments: Span<felt252>,
        ) {
            assert_auction_verifier(@self);
            assert(batch_id != 0, 'BAD_BATCH_ID');
            let mut index = 0;
            let len = commitments.len();
            loop {
                if index == len {
                    break;
                }

                let commitment = *commitments.at(index);
                assert(commitment != 0, 'BAD_COMMITMENT');
                let exists = self.note_commitments.read(commitment);
                assert(exists == false, 'NOTE_EXISTS');
                self.note_commitments.write(commitment, true);
                self.note_commitment_batch_ids.write(commitment, batch_id);
                index += 1;
            };
        }

        fn register_deposit_note_commitment(ref self: ContractState, commitment: felt252) {
            assert_deposit_registrar(@self);
            assert(commitment != 0, 'BAD_COMMITMENT');
            let exists = self.note_commitments.read(commitment);
            assert(exists == false, 'NOTE_EXISTS');
            self.note_commitments.write(commitment, true);
            self.note_commitment_batch_ids.write(commitment, 0);
            let auction_verifier = self.auction_verifier.read();
            if !auction_verifier.is_zero() {
                let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
                verifier.activate_deposit_note_root(commitment);
            }
        }

        fn is_order_commitment_registered(self: @ContractState, commitment: felt252) -> bool {
            self.order_commitments.read(commitment)
        }

        fn is_note_commitment_registered(self: @ContractState, commitment: felt252) -> bool {
            self.note_commitments.read(commitment)
        }

        fn order_commitment_batch(self: @ContractState, commitment: felt252) -> felt252 {
            self.order_commitment_batch_ids.read(commitment)
        }

        fn note_commitment_batch(self: @ContractState, commitment: felt252) -> felt252 {
            self.note_commitment_batch_ids.read(commitment)
        }

        fn batch_registrar_address(self: @ContractState) -> ContractAddress {
            self.batch_registrar.read()
        }

        fn privacy_deposit_bridge_address(self: @ContractState) -> ContractAddress {
            self.privacy_deposit_bridge.read()
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_batch_registrar(self: @ContractState) {
        assert(get_caller_address() == self.batch_registrar.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }

    fn assert_deposit_registrar(self: @ContractState) {
        assert(get_caller_address() == self.privacy_deposit_bridge.read(), 'UNAUTHORIZED');
    }
}

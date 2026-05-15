use starknet::ContractAddress;

#[starknet::interface]
pub trait ICommitmentRegistry<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
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
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
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
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
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
        fn propose_admin(ref self: ContractState, new_admin: ContractAddress) {
            assert_admin(@self);
            assert(!new_admin.is_zero(), 'BAD_ADMIN');
            assert(new_admin != self.admin.read(), 'BAD_ADMIN');
            self.pending_admin.write(new_admin);
            self.admin_transfer_pending.write(true);
        }

        fn accept_admin(ref self: ContractState) {
            let caller = get_caller_address();
            assert(self.admin_transfer_pending.read(), 'NO_ADMIN_TRANSFER');
            assert(caller == self.pending_admin.read(), 'UNAUTHORIZED');
            self.admin.write(caller);
            self.admin_transfer_pending.write(false);
        }

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

        fn admin_address(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn pending_admin_address(self: @ContractState) -> ContractAddress {
            self.pending_admin.read()
        }

        fn admin_transfer_pending(self: @ContractState) -> bool {
            self.admin_transfer_pending.read()
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

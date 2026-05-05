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
    fn consume_nullifiers(ref self: TContractState, nullifiers: Span<felt252>);
    fn consume_renewal_children(
        ref self: TContractState,
        parent_order_commitments: Span<felt252>,
        child_nullifiers: Span<felt252>,
    );
    fn cancel_renewal_parent(
        ref self: TContractState,
        parent_order_commitment: felt252,
        parent_secret_commitment: felt252,
        cancellation_nullifier: felt252,
        cancel_authority: felt252,
        signature_r: felt252,
        signature_s: felt252,
    );
    fn is_order_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_note_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_nullifier_consumed(self: @TContractState, nullifier: felt252) -> bool;
    fn is_renewal_child_consumed(self: @TContractState, child_nullifier: felt252) -> bool;
    fn is_renewal_parent_cancelled(
        self: @TContractState, parent_order_commitment: felt252,
    ) -> bool;
    fn renewal_parent_cancel_message_hash(
        self: @TContractState,
        parent_order_commitment: felt252,
        parent_secret_commitment: felt252,
        cancellation_nullifier: felt252,
    ) -> felt252;
    fn order_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn note_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn batch_registrar_address(self: @TContractState) -> ContractAddress;
    fn privacy_deposit_bridge_address(self: @TContractState) -> ContractAddress;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CommitmentRegistry {
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address};

    const RENEWAL_PARENT_CANCEL_DOMAIN: felt252 =
        0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3;
    const RENEWAL_PARENT_DOMAIN: felt252 =
        0x3c16da1b34d6fcc6f6ea27674de3b6cead275b20c1dfafa4abb43515a8974b4;

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
        consumed_nullifiers: Map<felt252, bool>,
        renewal_parent_cancelled: Map<felt252, bool>,
        renewal_cancellation_nullifiers: Map<felt252, bool>,
        renewal_child_nullifiers: Map<felt252, bool>,
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
        }

        fn consume_nullifiers(ref self: ContractState, nullifiers: Span<felt252>) {
            assert_auction_verifier(@self);
            let mut index = 0;
            let len = nullifiers.len();
            loop {
                if index == len {
                    break;
                }

                let nullifier = *nullifiers.at(index);
                assert(nullifier != 0, 'BAD_NULLIFIER');
                let already_consumed = self.consumed_nullifiers.read(nullifier);
                assert(already_consumed == false, 'NULLIFIER_USED');
                self.consumed_nullifiers.write(nullifier, true);
                index += 1;
            };
        }

        fn consume_renewal_children(
            ref self: ContractState,
            parent_order_commitments: Span<felt252>,
            child_nullifiers: Span<felt252>,
        ) {
            assert_auction_verifier(@self);
            assert(parent_order_commitments.len() == child_nullifiers.len(), 'BAD_RENEWAL_LEN');
            let mut index = 0;
            let len = child_nullifiers.len();
            loop {
                if index == len {
                    break;
                }

                let parent_order_commitment = *parent_order_commitments.at(index);
                let child_nullifier = *child_nullifiers.at(index);
                assert(parent_order_commitment != 0, 'BAD_RENEWAL_PARENT');
                assert(child_nullifier != 0, 'BAD_RENEWAL_CHILD');
                let parent_cancelled = self.renewal_parent_cancelled
                    .read(parent_order_commitment);
                assert(parent_cancelled == false, 'RENEWAL_PARENT_CANCELLED');
                let already_consumed = self.renewal_child_nullifiers.read(child_nullifier);
                assert(already_consumed == false, 'RENEWAL_CHILD_USED');
                self.renewal_child_nullifiers.write(child_nullifier, true);
                index += 1;
            };
        }

        fn cancel_renewal_parent(
            ref self: ContractState,
            parent_order_commitment: felt252,
            parent_secret_commitment: felt252,
            cancellation_nullifier: felt252,
            cancel_authority: felt252,
            signature_r: felt252,
            signature_s: felt252,
        ) {
            assert(parent_order_commitment != 0, 'BAD_RENEWAL_PARENT');
            assert(parent_secret_commitment != 0, 'BAD_PARENT_SECRET');
            assert(cancellation_nullifier != 0, 'BAD_CANCEL_NULLIFIER');
            assert(cancel_authority != 0, 'BAD_CANCEL_AUTHORITY');
            assert(signature_r != 0, 'BAD_CANCEL_SIG');
            assert(signature_s != 0, 'BAD_CANCEL_SIG');
            assert(
                compute_renewal_parent_commitment(parent_secret_commitment, cancel_authority)
                    == parent_order_commitment,
                'BAD_RENEWAL_PARENT_AUTH',
            );
            let cancellation_used = self.renewal_cancellation_nullifiers
                .read(cancellation_nullifier);
            assert(cancellation_used == false, 'CANCEL_NULLIFIER_USED');
            assert(
                check_ecdsa_signature(
                    compute_renewal_parent_cancel_message_hash(
                        parent_order_commitment, parent_secret_commitment, cancellation_nullifier,
                    ),
                    cancel_authority,
                    signature_r,
                    signature_s,
                ),
                'BAD_CANCEL_SIG',
            );
            self.renewal_parent_cancelled.write(parent_order_commitment, true);
            self.renewal_cancellation_nullifiers.write(cancellation_nullifier, true);
        }

        fn is_order_commitment_registered(self: @ContractState, commitment: felt252) -> bool {
            self.order_commitments.read(commitment)
        }

        fn is_note_commitment_registered(self: @ContractState, commitment: felt252) -> bool {
            self.note_commitments.read(commitment)
        }

        fn is_nullifier_consumed(self: @ContractState, nullifier: felt252) -> bool {
            self.consumed_nullifiers.read(nullifier)
        }

        fn is_renewal_child_consumed(self: @ContractState, child_nullifier: felt252) -> bool {
            self.renewal_child_nullifiers.read(child_nullifier)
        }

        fn is_renewal_parent_cancelled(
            self: @ContractState, parent_order_commitment: felt252,
        ) -> bool {
            self.renewal_parent_cancelled.read(parent_order_commitment)
        }

        fn renewal_parent_cancel_message_hash(
            self: @ContractState,
            parent_order_commitment: felt252,
            parent_secret_commitment: felt252,
            cancellation_nullifier: felt252,
        ) -> felt252 {
            compute_renewal_parent_cancel_message_hash(
                parent_order_commitment, parent_secret_commitment, cancellation_nullifier,
            )
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

    fn compute_renewal_parent_commitment(
        parent_secret_commitment: felt252, cancel_authority: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(RENEWAL_PARENT_DOMAIN, parent_secret_commitment);
        poseidon_hash2(state, cancel_authority)
    }

    fn compute_renewal_parent_cancel_message_hash(
        parent_order_commitment: felt252,
        parent_secret_commitment: felt252,
        cancellation_nullifier: felt252,
    ) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let mut state = poseidon_hash2(RENEWAL_PARENT_CANCEL_DOMAIN, tx_info.chain_id);
        state = poseidon_hash2(state, get_contract_address().into());
        state = poseidon_hash2(state, parent_order_commitment);
        state = poseidon_hash2(state, parent_secret_commitment);
        poseidon_hash2(state, cancellation_nullifier)
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }
}

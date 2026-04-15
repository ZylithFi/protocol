#[starknet::interface]
pub trait ICommitmentRegistry<TContractState> {
    fn register_order_commitments(
        ref self: TContractState, batch_id: felt252, commitments: Span<felt252>
    );
    fn register_note_commitments(
        ref self: TContractState, batch_id: felt252, commitments: Span<felt252>
    );
    fn register_deposit_note_commitment(ref self: TContractState, commitment: felt252);
    fn consume_nullifiers(ref self: TContractState, nullifiers: Span<felt252>);
    fn is_order_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_note_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_nullifier_consumed(self: @TContractState, nullifier: felt252) -> bool;
    fn order_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn note_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
}

#[starknet::contract]
pub mod CommitmentRegistry {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    #[storage]
    struct Storage {
        order_commitments: Map<felt252, bool>,
        order_commitment_batch_ids: Map<felt252, felt252>,
        note_commitments: Map<felt252, bool>,
        note_commitment_batch_ids: Map<felt252, felt252>,
        consumed_nullifiers: Map<felt252, bool>,
    }

    #[abi(embed_v0)]
    impl CommitmentRegistryImpl of super::ICommitmentRegistry<ContractState> {
        fn register_order_commitments(
            ref self: ContractState, batch_id: felt252, commitments: Span<felt252>
        ) {
            let mut index = 0;
            let len = commitments.len();
            loop {
                if index == len {
                    break;
                }

                let commitment = *commitments.at(index);
                let exists = self.order_commitments.read(commitment);
                assert(exists == false, 'ORDER_EXISTS');
                self.order_commitments.write(commitment, true);
                self.order_commitment_batch_ids.write(commitment, batch_id);
                index += 1;
            };
        }

        fn register_note_commitments(
            ref self: ContractState, batch_id: felt252, commitments: Span<felt252>
        ) {
            let mut index = 0;
            let len = commitments.len();
            loop {
                if index == len {
                    break;
                }

                let commitment = *commitments.at(index);
                let exists = self.note_commitments.read(commitment);
                assert(exists == false, 'NOTE_EXISTS');
                self.note_commitments.write(commitment, true);
                self.note_commitment_batch_ids.write(commitment, batch_id);
                index += 1;
            };
        }

        fn register_deposit_note_commitment(ref self: ContractState, commitment: felt252) {
            let exists = self.note_commitments.read(commitment);
            assert(exists == false, 'NOTE_EXISTS');
            self.note_commitments.write(commitment, true);
            self.note_commitment_batch_ids.write(commitment, 0);
        }

        fn consume_nullifiers(ref self: ContractState, nullifiers: Span<felt252>) {
            let mut index = 0;
            let len = nullifiers.len();
            loop {
                if index == len {
                    break;
                }

                let nullifier = *nullifiers.at(index);
                let already_consumed = self.consumed_nullifiers.read(nullifier);
                assert(already_consumed == false, 'NULLIFIER_USED');
                self.consumed_nullifiers.write(nullifier, true);
                index += 1;
            };
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

        fn order_commitment_batch(self: @ContractState, commitment: felt252) -> felt252 {
            self.order_commitment_batch_ids.read(commitment)
        }

        fn note_commitment_batch(self: @ContractState, commitment: felt252) -> felt252 {
            self.note_commitment_batch_ids.read(commitment)
        }
    }
}

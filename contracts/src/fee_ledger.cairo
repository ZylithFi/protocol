#[starknet::interface]
pub trait IFeeLedger<TContractState> {
    fn accrue_fees(
        ref self: TContractState,
        asset_ids: Span<felt252>,
        recipients: Span<felt252>,
        amounts: Span<u128>,
    );
    fn accrued_fee(self: @TContractState, asset_id: felt252, recipient: felt252) -> u128;
}

#[starknet::contract]
pub mod FeeLedger {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    #[storage]
    struct Storage {
        accrued_fees: Map<(felt252, felt252), u128>,
    }

    #[abi(embed_v0)]
    impl FeeLedgerImpl of super::IFeeLedger<ContractState> {
        fn accrue_fees(
            ref self: ContractState,
            asset_ids: Span<felt252>,
            recipients: Span<felt252>,
            amounts: Span<u128>,
        ) {
            let len = asset_ids.len();
            assert(recipients.len() == len, 'BAD_FEE_LENGTH');
            assert(amounts.len() == len, 'BAD_FEE_LENGTH');

            let mut index = 0;
            loop {
                if index == len {
                    break;
                }

                let asset_id = *asset_ids.at(index);
                let recipient = *recipients.at(index);
                let amount = *amounts.at(index);
                let current = self.accrued_fees.read((asset_id, recipient));
                self.accrued_fees.write((asset_id, recipient), current + amount);
                index += 1;
            };
        }

        fn accrued_fee(self: @ContractState, asset_id: felt252, recipient: felt252) -> u128 {
            self.accrued_fees.read((asset_id, recipient))
        }
    }
}
